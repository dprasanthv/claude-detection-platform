"""Phase 5 eval harness.

Runs one or more triagers (``MockTriager``, optionally ``ClaudeTriager``) against
the hand-labeled ground truth at ``evals/ground_truth.yaml`` and emits both a
machine-readable JSON report and a human-readable Markdown report under
``evals/reports/``.

Two collapse modes are reported in parallel because they answer different
real-world questions:

- ``strict`` — ``needs_investigation`` predictions count as *wrong* against any
  binary ground-truth label. Answers "did the triager produce a confident,
  actionable verdict?"
- ``lenient`` — ``needs_investigation`` predictions are folded into
  ``true_positive`` (i.e., "the analyst will look at it"). Answers "did the
  triager at least *escalate* what needed escalating?"

The harness is designed to run hermetically with the offline mock so the seed
report ships in the repo without an Anthropic API key. Pass ``--claude`` (or
set ``ANTHROPIC_API_KEY`` and use ``--both``) to run the live model.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml

from cdp.engine import DEFAULT_RULES_DIR, DetectionEngine
from cdp.enrich import DEFAULT_ASSET_DB, enrich_alert, load_asset_db
from cdp.ingest import generate_synthetic_dataset
from cdp.models import Alert, EnrichedAlert, TriageResult
from cdp.playbook import make_playbook_generator  # noqa: F401  (imported for parity / future use)
from cdp.store import Store
from cdp.triage import ClaudeTriager, MockTriager, Triager

REPO_ROOT = Path(__file__).resolve().parent.parent
GROUND_TRUTH = REPO_ROOT / "evals" / "ground_truth.yaml"
REPORTS_DIR = REPO_ROOT / "evals" / "reports"

Verdict = Literal["true_positive", "false_positive", "needs_investigation"]
GroundTruthLabel = Literal["true_positive", "false_positive"]
CollapseMode = Literal["strict", "lenient"]


# ---------- data classes ----------


@dataclass
class EvalCase:
    """A single labeled ground-truth row."""

    alert_id: str
    rule_id: str
    ground_truth: GroundTruthLabel
    rationale: str


@dataclass
class EvalPrediction:
    """One triager's verdict on one EvalCase."""

    alert_id: str
    rule_id: str
    ground_truth: GroundTruthLabel
    predicted: Verdict
    confidence: float
    reasoning: str
    rationale: str  # carried forward from the ground-truth row


@dataclass
class BinaryMetrics:
    """Precision / recall / F1 for one class (TP-as-positive or FP-as-positive)."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class ModeMetrics:
    """All metrics for one (triager, collapse-mode) cell."""

    mode: CollapseMode
    n: int
    correct: int
    accuracy: float
    tp_class: BinaryMetrics  # TP-as-positive
    fp_class: BinaryMetrics  # FP-as-positive
    confusion: dict[str, dict[str, int]]  # rows=truth, cols=predicted (3-way for strict; 2-way after collapse for lenient)


@dataclass
class TriagerResults:
    """All results + metrics for one triager."""

    triager_name: str
    model: str
    predictions: list[EvalPrediction] = field(default_factory=list)
    strict: ModeMetrics | None = None
    lenient: ModeMetrics | None = None
    per_rule_accuracy_strict: dict[str, dict[str, Any]] = field(default_factory=dict)


# ---------- ground truth I/O ----------


def load_ground_truth(path: Path = GROUND_TRUTH) -> list[EvalCase]:
    """Parse ``evals/ground_truth.yaml`` into a list of :class:`EvalCase`."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict) or "alerts" not in raw:
        raise ValueError(f"{path} must be a mapping with an 'alerts' list")
    cases: list[EvalCase] = []
    for row in raw["alerts"]:
        verdict = row["verdict"]
        if verdict not in ("true_positive", "false_positive"):
            raise ValueError(
                f"ground-truth verdict must be true_positive or false_positive, "
                f"got {verdict!r} for {row['alert_id']}"
            )
        cases.append(EvalCase(
            alert_id=row["alert_id"],
            rule_id=row["rule_id"],
            ground_truth=verdict,
            rationale=row.get("rationale", ""),
        ))
    return cases


# ---------- alert resolution ----------


def resolve_alerts(
    cases: list[EvalCase],
    *,
    rules_dir: Path = DEFAULT_RULES_DIR,
    data_dir: Path | None = None,
) -> dict[str, Alert]:
    """Re-run ingest + detection and return alerts keyed by id, filtered to the
    set referenced by ``cases``. Raises if any labeled alert is missing — that
    means the ground-truth file is stale relative to ``cdp/ingest.py``."""
    data_dir = data_dir or REPO_ROOT / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    generate_synthetic_dataset(data_dir)

    with Store(data_dir=data_dir) as store:
        store.load_all()
        engine = DetectionEngine(store, rules_dir=rules_dir)
        engine.load_rules()
        alerts = engine.run_all()

    by_id = {a.id: a for a in alerts}
    wanted = {c.alert_id for c in cases}
    missing = wanted - set(by_id)
    if missing:
        raise RuntimeError(
            f"{len(missing)} ground-truth alert(s) are not in the latest "
            f"detection run. Re-run `python evals/_build_ground_truth.py` "
            f"after any change to cdp/ingest.py.\n  Missing: {sorted(missing)[:5]}"
        )
    return {aid: by_id[aid] for aid in wanted}


# ---------- predictions ----------


def predict(
    triager: Triager,
    cases: list[EvalCase],
    alerts_by_id: dict[str, Alert],
    *,
    asset_db: dict[str, Any] | None = None,
) -> list[EvalPrediction]:
    """Run a triager against every case and collect predictions."""
    db = asset_db if asset_db is not None else load_asset_db(DEFAULT_ASSET_DB)
    out: list[EvalPrediction] = []
    for case in cases:
        alert = alerts_by_id[case.alert_id]
        enriched = EnrichedAlert(alert=alert, enrichment=enrich_alert(alert, db))
        result: TriageResult = triager.triage(enriched)
        out.append(EvalPrediction(
            alert_id=case.alert_id,
            rule_id=case.rule_id,
            ground_truth=case.ground_truth,
            predicted=result.verdict,
            confidence=result.confidence,
            reasoning=result.reasoning,
            rationale=case.rationale,
        ))
    return out


# ---------- metrics ----------


def _collapse(predicted: Verdict, mode: CollapseMode) -> GroundTruthLabel:
    """Map a 3-way verdict onto the binary ground-truth space.

    ``strict``  — ``needs_investigation`` is treated as ``false_positive``
    (i.e., 'didn't confidently catch the attack'). This is the harshest
    judgement: a TP-truth alert that the triager flags ``needs_investigation``
    counts as a miss.

    ``lenient`` — ``needs_investigation`` is treated as ``true_positive``
    (i.e., 'the analyst will look at it'). Reflects the SOC reality where
    escalation alone is often the correct outcome.
    """
    if predicted == "needs_investigation":
        return "true_positive" if mode == "lenient" else "false_positive"
    return predicted


def _binary_for(
    truth: GroundTruthLabel,
    predicted: GroundTruthLabel,
    positive_class: GroundTruthLabel,
) -> tuple[bool, bool, bool, bool]:
    """Return (tp, fp, fn, tn) booleans for one prediction wrt a positive class."""
    is_truth_pos = truth == positive_class
    is_pred_pos = predicted == positive_class
    return (
        is_truth_pos and is_pred_pos,
        not is_truth_pos and is_pred_pos,
        is_truth_pos and not is_pred_pos,
        not is_truth_pos and not is_pred_pos,
    )


def compute_mode_metrics(
    predictions: list[EvalPrediction],
    mode: CollapseMode,
) -> ModeMetrics:
    tp_class = BinaryMetrics()
    fp_class = BinaryMetrics()
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    correct = 0
    for p in predictions:
        collapsed = _collapse(p.predicted, mode)
        if collapsed == p.ground_truth:
            correct += 1
        # 3-way confusion (we record raw predicted) for transparency.
        confusion[p.ground_truth][p.predicted] += 1

        cls_metric_pairs: list[tuple[GroundTruthLabel, BinaryMetrics]] = [
            ("true_positive", tp_class),
            ("false_positive", fp_class),
        ]
        for cls, metric in cls_metric_pairs:
            tp, fp, fn, tn = _binary_for(p.ground_truth, collapsed, cls)
            metric.tp += int(tp)
            metric.fp += int(fp)
            metric.fn += int(fn)
            metric.tn += int(tn)

    return ModeMetrics(
        mode=mode,
        n=len(predictions),
        correct=correct,
        accuracy=correct / len(predictions) if predictions else 0.0,
        tp_class=tp_class,
        fp_class=fp_class,
        confusion={k: dict(v) for k, v in confusion.items()},
    )


def per_rule_accuracy(
    predictions: list[EvalPrediction], mode: CollapseMode
) -> dict[str, dict[str, Any]]:
    by_rule: dict[str, list[EvalPrediction]] = defaultdict(list)
    for p in predictions:
        by_rule[p.rule_id].append(p)
    out: dict[str, dict[str, Any]] = {}
    for rid, lst in sorted(by_rule.items()):
        n = len(lst)
        correct = sum(1 for p in lst if _collapse(p.predicted, mode) == p.ground_truth)
        out[rid] = {"n": n, "correct": correct, "accuracy": correct / n if n else 0.0}
    return out


# ---------- run ----------


def run(
    triagers: list[Triager],
    *,
    cases: list[EvalCase] | None = None,
    rules_dir: Path = DEFAULT_RULES_DIR,
    asset_db: dict[str, Any] | None = None,
    data_dir: Path | None = None,
    progress: Callable[[str], None] = lambda _: None,
) -> list[TriagerResults]:
    """End-to-end: load ground truth, resolve alerts, run each triager, compute metrics."""
    cases = cases or load_ground_truth()
    progress(f"loaded {len(cases)} ground-truth alerts")
    alerts_by_id = resolve_alerts(cases, rules_dir=rules_dir, data_dir=data_dir)
    progress(f"resolved {len(alerts_by_id)} alerts from latest detection run")
    db = asset_db if asset_db is not None else load_asset_db(DEFAULT_ASSET_DB)

    out: list[TriagerResults] = []
    for triager in triagers:
        name = type(triager).__name__
        progress(f"running {name} ({triager.model})")
        preds = predict(triager, cases, alerts_by_id, asset_db=db)
        out.append(TriagerResults(
            triager_name=name,
            model=triager.model,
            predictions=preds,
            strict=compute_mode_metrics(preds, "strict"),
            lenient=compute_mode_metrics(preds, "lenient"),
            per_rule_accuracy_strict=per_rule_accuracy(preds, "strict"),
        ))
    return out


# ---------- report rendering ----------


def to_json(results: list[TriagerResults]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "triagers": [
            {
                "name": r.triager_name,
                "model": r.model,
                "predictions": [asdict(p) for p in r.predictions],
                "strict": _modemetrics_to_dict(r.strict),
                "lenient": _modemetrics_to_dict(r.lenient),
                "per_rule_accuracy_strict": r.per_rule_accuracy_strict,
            }
            for r in results
        ],
    }


def _modemetrics_to_dict(m: ModeMetrics | None) -> dict[str, Any] | None:
    if m is None:
        return None
    return {
        "mode": m.mode,
        "n": m.n,
        "correct": m.correct,
        "accuracy": m.accuracy,
        "tp_class": {
            "precision": m.tp_class.precision,
            "recall": m.tp_class.recall,
            "f1": m.tp_class.f1,
            **asdict(m.tp_class),
        },
        "fp_class": {
            "precision": m.fp_class.precision,
            "recall": m.fp_class.recall,
            "f1": m.fp_class.f1,
            **asdict(m.fp_class),
        },
        "confusion": m.confusion,
    }


def to_markdown(results: list[TriagerResults], *, title: str = "Eval report") -> str:
    """Render a human-readable Markdown report."""
    ts = datetime.now(UTC).isoformat(timespec="seconds")
    lines: list[str] = [
        f"# {title}",
        "",
        f"_Generated: {ts}_",
        "",
        f"Ground-truth file: `evals/ground_truth.yaml` "
        f"({results[0].strict.n if results and results[0].strict else 0} alerts)",
        "",
    ]

    # ---- summary table across triagers + collapse modes ----
    lines += [
        "## Summary",
        "",
        "| Triager | Model | Mode | Accuracy | TP precision | TP recall | TP F1 | FP precision | FP recall | FP F1 |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        for m in (r.strict, r.lenient):
            if m is None:
                continue
            lines.append(
                f"| {r.triager_name} | `{r.model}` | {m.mode} | "
                f"{m.accuracy:.2%} ({m.correct}/{m.n}) | "
                f"{m.tp_class.precision:.2%} | {m.tp_class.recall:.2%} | {m.tp_class.f1:.2%} | "
                f"{m.fp_class.precision:.2%} | {m.fp_class.recall:.2%} | {m.fp_class.f1:.2%} |"
            )
    lines.append("")

    # ---- per-triager detail ----
    for r in results:
        lines += [
            f"## {r.triager_name} (`{r.model}`)",
            "",
            "### Confusion matrix (3-way, strict)",
            "",
            "Rows are ground truth; columns are the triager's raw verdict.",
            "",
            "| | TP predicted | FP predicted | NI predicted |",
            "|---|---:|---:|---:|",
        ]
        if r.strict is None:
            continue
        for truth in ("true_positive", "false_positive"):
            row = r.strict.confusion.get(truth, {})
            lines.append(
                f"| {truth} | "
                f"{row.get('true_positive', 0)} | "
                f"{row.get('false_positive', 0)} | "
                f"{row.get('needs_investigation', 0)} |"
            )
        lines.append("")
        lines += [
            "### Per-rule accuracy (strict)",
            "",
            "| Rule | n | correct | accuracy |",
            "|---|---:|---:|---:|",
        ]
        for rid, stats in r.per_rule_accuracy_strict.items():
            lines.append(
                f"| `{rid}` | {stats['n']} | {stats['correct']} | "
                f"{stats['accuracy']:.2%} |"
            )
        lines.append("")

        # ---- disagreements (strict mode) ----
        disagreements = [
            p for p in r.predictions
            if _collapse(p.predicted, "strict") != p.ground_truth
        ]
        lines.append(f"### Disagreements (strict): {len(disagreements)} of {len(r.predictions)}")
        lines.append("")
        if not disagreements:
            lines.append("_None._")
        else:
            for p in disagreements:
                lines += [
                    f"- **`{p.alert_id}`** — truth=`{p.ground_truth}`, "
                    f"predicted=`{p.predicted}` (confidence {p.confidence:.2f})",
                    f"  - Ground-truth rationale: {p.rationale}",
                    f"  - Triager reasoning: {p.reasoning}",
                ]
        lines.append("")

    # ---- methodology footer ----
    lines += [
        "---",
        "",
        "### Methodology notes",
        "",
        "- **Ground truth** is hand-labeled by the project author against the "
        "deterministic synthetic dataset (`cdp/ingest.py`). Labels are binary "
        "(`true_positive` / `false_positive`); see `evals/ground_truth.yaml` "
        "for per-alert rationale.",
        "- **Strict mode** counts a `needs_investigation` prediction as wrong. "
        "**Lenient mode** counts it as `true_positive` (the analyst will "
        "review it).",
        "- **TP-class metrics** treat `true_positive` as the positive label. "
        "**FP-class metrics** treat `false_positive` as the positive label "
        "(useful when you care about false-positive *recall* — i.e., how "
        "many of the FPs the triager correctly suppressed).",
        "- The mock triager is a stable baseline — its job is to make the "
        "Claude triager's *lift* visible, not to be SOTA itself.",
    ]

    return "\n".join(lines) + "\n"


# ---------- triager construction ----------


def build_triagers(
    *,
    use_mock: bool,
    use_claude: bool,
    settings: Any | None = None,
) -> list[Triager]:
    triagers: list[Triager] = []
    if use_mock:
        triagers.append(MockTriager())
    if use_claude:
        from cdp.config import Settings

        cfg = settings or Settings.load()
        if not cfg.has_anthropic_key:
            raise RuntimeError(
                "--claude requested but ANTHROPIC_API_KEY is not set. "
                "Either set it or drop --claude."
            )
        assert cfg.anthropic_api_key is not None
        triagers.append(ClaudeTriager(
            api_key=cfg.anthropic_api_key,
            model=cfg.model,
        ))
    if not triagers:
        raise RuntimeError("must enable at least one triager")
    return triagers


# ---------- main ----------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 5 eval harness")
    parser.add_argument("--mock", action="store_true", help="Run MockTriager (default).")
    parser.add_argument("--claude", action="store_true", help="Run ClaudeTriager (requires ANTHROPIC_API_KEY).")
    parser.add_argument("--both", action="store_true", help="Shorthand for --mock --claude.")
    parser.add_argument(
        "--out-name",
        default="latest",
        help="Report filename stem under evals/reports/ (default: 'latest').",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    use_mock = args.mock or args.both or not (args.mock or args.claude or args.both)
    use_claude = args.claude or args.both

    triagers = build_triagers(use_mock=use_mock, use_claude=use_claude)

    def progress(msg: str) -> None:
        if not args.quiet:
            print(f"[eval] {msg}", file=sys.stderr)

    results = run(triagers, progress=progress)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    md_path = REPORTS_DIR / f"{args.out_name}.md"
    json_path = REPORTS_DIR / f"{args.out_name}.json"
    title = "Eval report — " + " + ".join(r.triager_name for r in results)
    md_path.write_text(to_markdown(results, title=title))
    json_path.write_text(json.dumps(to_json(results), indent=2))

    print(f"wrote {md_path.relative_to(REPO_ROOT)}")
    print(f"wrote {json_path.relative_to(REPO_ROOT)}")
    # Convenience: print the headline accuracy line.
    for r in results:
        if r.strict:
            print(
                f"  {r.triager_name:>20s}  strict acc {r.strict.accuracy:.2%} "
                f"({r.strict.correct}/{r.strict.n})  "
                f"TP-F1 {r.strict.tp_class.f1:.2%}  FP-F1 {r.strict.fp_class.f1:.2%}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
