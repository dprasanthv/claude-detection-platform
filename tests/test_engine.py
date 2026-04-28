"""End-to-end detection engine.

These tests pin the *exact* per-rule alert counts produced against the
deterministic synthetic dataset. Anyone changing the dataset, the rules, or
the engine semantics must update the expected counts here on purpose — that's
the point. Surprise drift gets caught.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cdp.engine import DetectionEngine
from cdp.store import Store

EXPECTED_PER_RULE_COUNTS = {
    "cdp.credential_access.brute_force_admin_login": 50,
    "cdp.credential_access.iam_admin_policy_attached": 1,
    "cdp.execution.powershell_encoded_command": 1,
    "cdp.execution.office_spawns_script_host": 2,
    "cdp.persistence.new_service_install": 1,
    "cdp.exfiltration.s3_large_object_egress": 25,
}
EXPECTED_TOTAL_ALERTS = sum(EXPECTED_PER_RULE_COUNTS.values())  # 80
REQUIRED_TACTICS = frozenset(
    {"credential_access", "execution", "persistence", "exfiltration"}
)


def test_engine_emits_expected_per_rule_counts(
    seeded_store: Store, detections_dir: Path
) -> None:
    engine = DetectionEngine(seeded_store, rules_dir=detections_dir)
    rules = engine.load_rules()
    alerts = engine.run_all()

    assert len(rules) == len(EXPECTED_PER_RULE_COUNTS)
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a.rule_id] = counts.get(a.rule_id, 0) + 1
    assert counts == EXPECTED_PER_RULE_COUNTS
    assert len(alerts) == EXPECTED_TOTAL_ALERTS


def test_engine_covers_all_four_required_tactics(
    seeded_store: Store, detections_dir: Path
) -> None:
    engine = DetectionEngine(seeded_store, rules_dir=detections_dir)
    alerts = engine.run_all()
    fired_tactics = {
        tag.removeprefix("attack.")
        for a in alerts
        for tag in a.rule_tags
        if tag.startswith("attack.") and not tag.startswith("attack.t")
    }
    assert fired_tactics >= REQUIRED_TACTICS


def test_alert_ids_are_deterministic_across_runs(
    seeded_store: Store, detections_dir: Path
) -> None:
    """Same dataset + same rules ⇒ identical alert ids. This is what makes
    Phase 5's ground-truth labels stable across CI runs."""
    e1 = DetectionEngine(seeded_store, rules_dir=detections_dir)
    e2 = DetectionEngine(seeded_store, rules_dir=detections_dir)
    a1 = sorted(a.id for a in e1.run_all())
    a2 = sorted(a.id for a in e2.run_all())
    assert a1 == a2
    # And the id format is the documented ``{rule_id}-{12 hex chars}``.
    for alert_id in a1:
        rule_id, _, suffix = alert_id.rpartition("-")
        assert rule_id  # non-empty
        assert len(suffix) == 12
        int(suffix, 16)  # raises if not hex


def test_alert_carries_rule_metadata(
    seeded_store: Store, detections_dir: Path
) -> None:
    engine = DetectionEngine(seeded_store, rules_dir=detections_dir)
    alerts = engine.run_all()
    a = next(x for x in alerts if x.rule_id == "cdp.execution.powershell_encoded_command")
    assert a.rule_level == "high"
    assert "T1059.001" in a.mitre_techniques
    assert a.logsource_table == "windows_process_creation"
    assert "EncodedCommand" in a.matched_event["CommandLine"]
    assert a.rule_sha256 is not None and len(a.rule_sha256) == 64


def test_engine_skips_rule_with_unmapped_logsource(
    seeded_store: Store, tmp_path: Path
) -> None:
    """A rule whose logsource doesn't match any known table is silently
    skipped — that's the documented behavior in ``engine.run_all``."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "linux_unmapped.yml").write_text(
        "title: t\nid: r\nlevel: low\n"
        "logsource:\n  product: linux\n  category: process_creation\n"
        "detection:\n  sel:\n    foo: bar\n  condition: sel\n"
        "tags:\n  - attack.discovery\n"
    )
    engine = DetectionEngine(seeded_store, rules_dir=rules_dir)
    engine.load_rules()
    assert engine.run_all() == []


def test_engine_skips_rule_when_table_not_loaded(tmp_path: Path) -> None:
    """If the parquet for a mapped table simply isn't loaded, the rule is
    skipped (no crash). Mirrors the partial-data startup case."""
    # Empty data dir → no tables loaded.
    store = Store(data_dir=tmp_path)
    store.load_all()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "auth_only.yml").write_text(
        "title: t\nid: r\nlevel: low\n"
        "logsource:\n  category: authentication\n"
        "detection:\n  sel:\n    username: admin\n  condition: sel\n"
        "tags:\n  - attack.credential_access\n"
    )
    engine = DetectionEngine(store, rules_dir=rules_dir)
    engine.load_rules()
    try:
        assert engine.run_all() == []
    finally:
        store.close()


def test_engine_missing_rules_dir_raises(
    seeded_store: Store, tmp_path: Path
) -> None:
    engine = DetectionEngine(seeded_store, rules_dir=tmp_path / "nope")
    with pytest.raises(FileNotFoundError):
        engine.load_rules()


def test_run_all_autoloads_rules_and_tables(
    seeded_data_dir: Path, detections_dir: Path
) -> None:
    """``run_all`` auto-loads rules and parquets if the caller hasn't yet."""
    store = Store(data_dir=seeded_data_dir)  # tables() == [] initially
    try:
        engine = DetectionEngine(store, rules_dir=detections_dir)
        alerts = engine.run_all()  # should self-bootstrap
        assert len(alerts) == EXPECTED_TOTAL_ALERTS
    finally:
        store.close()
