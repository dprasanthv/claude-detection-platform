"""Phase 5 eval-harness tests.

Two layers:

- **Pure-function math** — exercised on synthetic ``EvalPrediction`` lists so
  the metric definitions are nailed independently of the rest of the pipeline.
- **End-to-end** — runs the full harness against the real ground-truth file
  using the deterministic ``MockTriager``, asserting a tight set of expected
  metric values. This locks in the exact eval baseline the seed report
  records, so any drift in mock behavior or in the synthetic dataset is
  surfaced as a failing test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# `evals/` is a sibling top-level dir, not a subpackage of `cdp`. Make it
# importable for the test process the same way the `cdp eval` CLI subcommand
# does.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evals import run_eval  # noqa: E402
from evals.run_eval import (  # noqa: E402
    BinaryMetrics,
    EvalCase,
    EvalPrediction,
    GroundTruthLabel,
    Verdict,
    _collapse,
    compute_mode_metrics,
    load_ground_truth,
    per_rule_accuracy,
    to_json,
    to_markdown,
)

# ---------- helpers ----------


def _mk(
    truth: GroundTruthLabel,
    pred: Verdict,
    *,
    rule_id: str = "test.rule",
    confidence: float = 0.5,
) -> EvalPrediction:
    return EvalPrediction(
        alert_id=f"{rule_id}-{truth}-{pred}",
        rule_id=rule_id,
        ground_truth=truth,
        predicted=pred,
        confidence=confidence,
        reasoning="r",
        rationale="rationale",
    )


# ---------- _collapse ----------


@pytest.mark.parametrize(
    ("predicted", "mode", "expected"),
    [
        ("true_positive", "strict", "true_positive"),
        ("false_positive", "strict", "false_positive"),
        ("needs_investigation", "strict", "false_positive"),  # NI is wrong in strict
        ("true_positive", "lenient", "true_positive"),
        ("false_positive", "lenient", "false_positive"),
        ("needs_investigation", "lenient", "true_positive"),  # NI escalates in lenient
    ],
)
def test_collapse(predicted: Verdict, mode: str, expected: GroundTruthLabel) -> None:
    assert _collapse(predicted, mode) == expected  # type: ignore[arg-type]


# ---------- BinaryMetrics ----------


def test_binary_metrics_zero_division() -> None:
    m = BinaryMetrics()
    assert m.precision == 0.0
    assert m.recall == 0.0
    assert m.f1 == 0.0


def test_binary_metrics_perfect() -> None:
    m = BinaryMetrics(tp=10, fp=0, fn=0, tn=5)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.f1 == 1.0


def test_binary_metrics_typical() -> None:
    # 8 / (8+2) = 0.8 precision; 8 / (8+4) = 0.667 recall; F1 = 2*.8*.667/(.8+.667) ≈ 0.727
    m = BinaryMetrics(tp=8, fp=2, fn=4, tn=6)
    assert m.precision == pytest.approx(0.8)
    assert m.recall == pytest.approx(8 / 12)
    assert m.f1 == pytest.approx(2 * 0.8 * (8 / 12) / (0.8 + 8 / 12))


# ---------- compute_mode_metrics ----------


def test_compute_mode_metrics_perfect_predictions() -> None:
    preds = [
        _mk("true_positive", "true_positive"),
        _mk("true_positive", "true_positive"),
        _mk("false_positive", "false_positive"),
    ]
    for mode in ("strict", "lenient"):
        m = compute_mode_metrics(preds, mode)  # type: ignore[arg-type]
        assert m.accuracy == 1.0
        assert m.correct == 3
        assert m.tp_class.precision == 1.0
        assert m.tp_class.recall == 1.0
        assert m.fp_class.precision == 1.0
        assert m.fp_class.recall == 1.0


def test_compute_mode_metrics_mock_baseline_pattern() -> None:
    """Mirrors the real Mock baseline: catches all TPs, misses all FPs."""
    preds = [
        _mk("true_positive", "true_positive"),
        _mk("true_positive", "true_positive"),
        _mk("false_positive", "true_positive"),  # mock flags FP truth as TP
    ]
    m = compute_mode_metrics(preds, "strict")
    assert m.accuracy == pytest.approx(2 / 3)
    # TP-class: 2 TP, 1 FP (the FP-truth pred), 0 FN, 0 TN.
    assert m.tp_class.tp == 2
    assert m.tp_class.fp == 1
    assert m.tp_class.recall == 1.0
    # FP-class: 0 TP, 0 FP, 1 FN (the FP-truth that was mispredicted), 2 TN.
    assert m.fp_class.tp == 0
    assert m.fp_class.recall == 0.0


def test_compute_mode_metrics_strict_vs_lenient_differ_on_NI() -> None:
    # Truth is TP, predicted is NI:
    # strict  → collapsed=FP → wrong; recall(TP)=0
    # lenient → collapsed=TP → right; recall(TP)=1
    preds = [_mk("true_positive", "needs_investigation")]
    strict = compute_mode_metrics(preds, "strict")
    lenient = compute_mode_metrics(preds, "lenient")
    assert strict.accuracy == 0.0
    assert lenient.accuracy == 1.0
    assert strict.tp_class.recall == 0.0
    assert lenient.tp_class.recall == 1.0


def test_confusion_matrix_records_raw_verdicts() -> None:
    """The 3-way confusion matrix preserves the original (un-collapsed)
    predicted verdict so a reader can see how often NI is being used."""
    preds = [
        _mk("true_positive", "true_positive"),
        _mk("true_positive", "needs_investigation"),
        _mk("false_positive", "true_positive"),
    ]
    m = compute_mode_metrics(preds, "strict")
    assert m.confusion["true_positive"]["true_positive"] == 1
    assert m.confusion["true_positive"]["needs_investigation"] == 1
    assert m.confusion["false_positive"]["true_positive"] == 1


# ---------- per_rule_accuracy ----------


def test_per_rule_accuracy_groups_by_rule_id() -> None:
    preds = [
        _mk("true_positive", "true_positive", rule_id="rule.a"),
        _mk("true_positive", "true_positive", rule_id="rule.a"),
        _mk("false_positive", "true_positive", rule_id="rule.a"),
        _mk("true_positive", "true_positive", rule_id="rule.b"),
    ]
    out = per_rule_accuracy(preds, "strict")
    assert out["rule.a"] == {"n": 3, "correct": 2, "accuracy": pytest.approx(2 / 3)}
    assert out["rule.b"] == {"n": 1, "correct": 1, "accuracy": 1.0}


# ---------- load_ground_truth ----------


def test_load_ground_truth_against_real_file() -> None:
    cases = load_ground_truth()
    assert len(cases) == 20
    assert sum(1 for c in cases if c.ground_truth == "true_positive") == 14
    assert sum(1 for c in cases if c.ground_truth == "false_positive") == 6


def test_load_ground_truth_rejects_invalid_verdict(tmp_path: Path) -> None:
    p = tmp_path / "gt.yaml"
    p.write_text(
        "version: 1\nalerts:\n"
        "- alert_id: a\n  rule_id: r\n  verdict: needs_investigation\n  rationale: ''\n"
    )
    with pytest.raises(ValueError, match="must be true_positive or false_positive"):
        load_ground_truth(p)


def test_load_ground_truth_rejects_missing_alerts_key(tmp_path: Path) -> None:
    p = tmp_path / "gt.yaml"
    p.write_text("version: 1\n")
    with pytest.raises(ValueError, match="must be a mapping with an 'alerts' list"):
        load_ground_truth(p)


# ---------- end-to-end with MockTriager ----------


def test_end_to_end_mock_baseline_metrics(synthetic_dataset_dir: Path) -> None:
    """Lock in the exact MockTriager performance against the seeded ground
    truth. Drift here means either the dataset shifted or the heuristic
    changed — both should be deliberate code changes, surfaced by this test.
    """
    from cdp.engine import DEFAULT_RULES_DIR
    from cdp.triage import MockTriager

    results = run_eval.run(
        [MockTriager()],
        rules_dir=DEFAULT_RULES_DIR,
        data_dir=synthetic_dataset_dir,
    )
    assert len(results) == 1
    r = results[0]
    assert r.triager_name == "MockTriager"
    assert r.strict is not None and r.lenient is not None

    # Ground truth: 14 TP + 6 FP. Mock catches all TPs, misses all FPs.
    assert r.strict.n == 20
    assert r.strict.correct == 14
    assert r.strict.accuracy == pytest.approx(0.70)
    # TP-class: 14 TP, 6 FP (the mispredicted FP-truths), 0 FN.
    assert r.strict.tp_class.tp == 14
    assert r.strict.tp_class.fp == 6
    assert r.strict.tp_class.recall == 1.0
    # FP-class: nothing right.
    assert r.strict.fp_class.tp == 0
    assert r.strict.fp_class.recall == 0.0
    # Lenient is identical here because mock never emits NI for these alerts.
    assert r.lenient.accuracy == pytest.approx(0.70)


def test_end_to_end_mock_per_rule_accuracy_matches_dataset(synthetic_dataset_dir: Path) -> None:
    """Per-rule breakdown: mock is 100% on the four rules with no FP truths,
    and below 100% on the two rules where ground truth includes FPs."""
    from cdp.engine import DEFAULT_RULES_DIR
    from cdp.triage import MockTriager

    results = run_eval.run(
        [MockTriager()],
        rules_dir=DEFAULT_RULES_DIR,
        data_dir=synthetic_dataset_dir,
    )
    by_rule = results[0].per_rule_accuracy_strict
    # TP-only rules: perfect.
    for rid in (
        "cdp.credential_access.iam_admin_policy_attached",
        "cdp.execution.powershell_encoded_command",
        "cdp.execution.office_spawns_script_host",
        "cdp.persistence.new_service_install",
    ):
        assert by_rule[rid]["accuracy"] == 1.0
    # Mixed rules: under 1.0 because mock misses the FPs.
    assert by_rule["cdp.credential_access.brute_force_admin_login"]["accuracy"] < 1.0
    assert by_rule["cdp.exfiltration.s3_large_object_egress"]["accuracy"] < 1.0


# ---------- report rendering ----------


def test_to_markdown_includes_summary_and_disagreements() -> None:
    preds = [
        _mk("true_positive", "true_positive", rule_id="r.a"),
        _mk("false_positive", "true_positive", rule_id="r.b"),
    ]
    results = [
        run_eval.TriagerResults(
            triager_name="MockTriager",
            model="m",
            predictions=preds,
            strict=compute_mode_metrics(preds, "strict"),
            lenient=compute_mode_metrics(preds, "lenient"),
            per_rule_accuracy_strict=per_rule_accuracy(preds, "strict"),
        )
    ]
    md = to_markdown(results, title="Test report")
    assert "# Test report" in md
    assert "## Summary" in md
    assert "Confusion matrix" in md
    assert "Disagreements (strict): 1 of 2" in md
    # The disagreement block names the alert id and ground truth.
    assert "false_positive" in md


def test_to_json_round_trips() -> None:
    preds = [_mk("true_positive", "true_positive")]
    results = [
        run_eval.TriagerResults(
            triager_name="MockTriager",
            model="m",
            predictions=preds,
            strict=compute_mode_metrics(preds, "strict"),
            lenient=compute_mode_metrics(preds, "lenient"),
            per_rule_accuracy_strict=per_rule_accuracy(preds, "strict"),
        )
    ]
    blob = to_json(results)
    # Must be JSON-serializable as-is (no datetime / dataclass weirdness leaked).
    text = json.dumps(blob)
    assert json.loads(text) == blob
    assert blob["schema_version"] == 1
    assert blob["triagers"][0]["strict"]["accuracy"] == 1.0


# ---------- build_triagers ----------


def test_build_triagers_default_to_mock() -> None:
    triagers = run_eval.build_triagers(use_mock=True, use_claude=False)
    assert len(triagers) == 1
    assert type(triagers[0]).__name__ == "MockTriager"


def test_build_triagers_claude_without_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from cdp.config import Settings

    # `monkeypatch.setenv` won't help because Settings.load() is called fresh,
    # so we patch the loaded settings directly via the kwarg.
    cfg = Settings(data_dir=Path("/tmp"), anthropic_api_key=None, model="m")
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        run_eval.build_triagers(use_mock=False, use_claude=True, settings=cfg)


def test_build_triagers_no_triager_raises() -> None:
    with pytest.raises(RuntimeError, match="must enable at least one"):
        run_eval.build_triagers(use_mock=False, use_claude=False)


# ---------- ground-truth ⇄ dataset coherence ----------


def test_every_ground_truth_alert_id_resolves(synthetic_dataset_dir: Path) -> None:
    """The harness raises a clear error if any labeled alert id is missing
    from the latest detection run — surface it as a regression test."""
    from cdp.engine import DEFAULT_RULES_DIR

    cases = load_ground_truth()
    by_id = run_eval.resolve_alerts(
        cases, rules_dir=DEFAULT_RULES_DIR, data_dir=synthetic_dataset_dir
    )
    assert len(by_id) == len(cases)
    for c in cases:
        assert c.alert_id in by_id
        assert by_id[c.alert_id].rule_id == c.rule_id


# ---------- imports cleanup (silence unused-warning for re-exported names) ----------


def test_eval_case_is_importable() -> None:
    EvalCase(alert_id="a", rule_id="r", ground_truth="true_positive", rationale="x")
