"""Typer CLI smoke tests using Click's :class:`CliRunner`.

These tests run the CLI in-process (no subprocess), so they're fast and
exercise the same code paths a user would hit at the terminal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cdp.cli import app

runner = CliRunner()


def test_version_prints_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, result.stdout
    assert "0.1.0" in result.stdout


def test_help_lists_every_subcommand() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in (
        "ingest", "detect", "validate",
        "enrich", "triage", "playbook",
        "eval", "serve", "demo", "version",
    ):
        assert cmd in result.stdout


# ---------- ingest ----------


def test_ingest_synthetic_writes_three_parquet_tables(tmp_data_dir: Path) -> None:
    result = runner.invoke(app, ["ingest", "--synthetic", "--data-dir", str(tmp_data_dir)])
    assert result.exit_code == 0, result.stdout
    for name in ("windows_process_creation", "authentication", "aws_cloudtrail"):
        assert (tmp_data_dir / f"{name}.parquet").exists()


def test_ingest_no_synthetic_no_mordor_errors(tmp_data_dir: Path) -> None:
    result = runner.invoke(app, ["ingest", "--no-synthetic"])
    assert result.exit_code != 0


def test_ingest_with_mordor_raises_not_implemented(tmp_data_dir: Path) -> None:
    result = runner.invoke(app, ["ingest", "--mordor", "apt29-day1"])
    assert result.exit_code != 0
    # Click/Typer surfaces the unhandled exception in the result.
    assert isinstance(result.exception, NotImplementedError) or "NotImplementedError" in str(
        result.exception
    )


# ---------- detect ----------


def test_detect_without_data_warns_and_exits_nonzero(tmp_data_dir: Path) -> None:
    """An empty data dir should print the warning and exit 1, not crash."""
    result = runner.invoke(app, ["detect"])
    assert result.exit_code == 1
    assert "ingest" in result.stdout.lower()


def test_detect_invalid_format_errors(tmp_data_dir: Path) -> None:
    result = runner.invoke(app, ["detect", "--format", "xml"])
    assert result.exit_code != 0


def test_detect_after_ingest_emits_alerts_as_json(
    tmp_data_dir: Path, detections_dir: Path
) -> None:
    ingest_result = runner.invoke(
        app, ["ingest", "--synthetic", "--data-dir", str(tmp_data_dir)]
    )
    assert ingest_result.exit_code == 0, ingest_result.stdout

    detect_result = runner.invoke(
        app,
        [
            "detect",
            "--rules-dir",
            str(detections_dir),
            "--format",
            "json",
        ],
    )
    assert detect_result.exit_code == 0, detect_result.stdout
    payload = json.loads(detect_result.stdout)
    assert isinstance(payload, list)
    assert len(payload) > 0
    expected_keys = {"id", "rule_id", "rule_level", "matched_event", "logsource_table"}
    for alert in payload:
        assert expected_keys <= alert.keys()


def test_detect_table_format_with_limit(
    tmp_data_dir: Path, detections_dir: Path
) -> None:
    runner.invoke(app, ["ingest", "--synthetic", "--data-dir", str(tmp_data_dir)])
    result = runner.invoke(
        app,
        ["detect", "--rules-dir", str(detections_dir), "--format", "table", "--limit", "3"],
    )
    assert result.exit_code == 0, result.stdout
    assert "Alerts" in result.stdout


# ---------- validate ----------


def test_validate_passes_on_shipped_rules(detections_dir: Path) -> None:
    result = runner.invoke(app, ["validate", "--rules-dir", str(detections_dir)])
    assert result.exit_code == 0, result.stdout
    assert "all rules valid" in result.stdout


def test_validate_strict_passes_on_shipped_rules(detections_dir: Path) -> None:
    """All shipped rules map to a known table, so ``--strict`` must also pass."""
    result = runner.invoke(
        app, ["validate", "--rules-dir", str(detections_dir), "--strict"]
    )
    assert result.exit_code == 0, result.stdout


def test_validate_fails_on_broken_rule(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yml").write_text(
        "title: t\nid: broken\nlevel: high\n"
        "logsource:\n  category: authentication\n"
        # Unsupported modifier triggers a compile-time failure.
        "detection:\n  sel:\n    a|wat: 1\n  condition: sel\n"
    )
    result = runner.invoke(app, ["validate", "--rules-dir", str(rules_dir)])
    assert result.exit_code == 1
    assert "broken" in result.stdout
    assert "unsupported modifier" in result.stdout.lower()


def test_validate_skips_unmapped_logsource_by_default(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "linux.yml").write_text(
        "title: t\nid: linux_only\nlevel: low\n"
        "logsource:\n  product: linux\n  category: process_creation\n"
        "detection:\n  sel:\n    foo: bar\n  condition: sel\n"
    )
    result = runner.invoke(app, ["validate", "--rules-dir", str(rules_dir)])
    assert result.exit_code == 0
    assert "skipped" in result.stdout.lower()


def test_validate_strict_treats_unmapped_logsource_as_failure(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "linux.yml").write_text(
        "title: t\nid: linux_only\nlevel: low\n"
        "logsource:\n  product: linux\n  category: process_creation\n"
        "detection:\n  sel:\n    foo: bar\n  condition: sel\n"
    )
    result = runner.invoke(app, ["validate", "--rules-dir", str(rules_dir), "--strict"])
    assert result.exit_code == 1
    assert "linux_only" in result.stdout


def test_validate_missing_rules_dir_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", "--rules-dir", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_validate_empty_rules_dir_exits_2(tmp_path: Path) -> None:
    rules_dir = tmp_path / "empty"
    rules_dir.mkdir()
    result = runner.invoke(app, ["validate", "--rules-dir", str(rules_dir)])
    assert result.exit_code == 2


# ---------- enrich / triage / playbook helpers ----------


def _detect_alerts_json(tmp_data_dir: Path, detections_dir: Path) -> str:
    """Run ingest + detect to produce the alerts JSON used by Phase 3 tests."""
    runner.invoke(app, ["ingest", "--synthetic", "--data-dir", str(tmp_data_dir)])
    result = runner.invoke(
        app,
        ["detect", "--rules-dir", str(detections_dir), "--format", "json"],
    )
    assert result.exit_code == 0, result.stdout
    return result.stdout


# ---------- enrich ----------


def test_enrich_reads_alert_from_file(
    tmp_data_dir: Path, detections_dir: Path, tmp_path: Path
) -> None:
    payload = _detect_alerts_json(tmp_data_dir, detections_dir)
    alerts = json.loads(payload)
    one = tmp_path / "one.json"
    one.write_text(json.dumps(alerts[0]))
    result = runner.invoke(app, ["enrich", "--alert-json", str(one)])
    assert result.exit_code == 0, result.stdout
    enriched = json.loads(result.stdout)
    assert isinstance(enriched, list)
    assert len(enriched) == 1
    assert enriched[0]["alert_id"] == alerts[0]["id"]


def test_enrich_with_no_input_exits_1(tmp_data_dir: Path) -> None:
    """No file and no stdin → graceful exit, not a crash."""
    result = runner.invoke(app, ["enrich"])
    assert result.exit_code == 1
    assert "no alerts" in result.stdout.lower()


# ---------- triage ----------


def test_triage_with_alert_id_runs_against_synthetic(
    tmp_data_dir: Path, detections_dir: Path
) -> None:
    payload = _detect_alerts_json(tmp_data_dir, detections_dir)
    alerts = json.loads(payload)
    target = next(a for a in alerts if a["rule_id"] == "cdp.execution.powershell_encoded_command")
    result = runner.invoke(
        app,
        [
            "triage",
            "--alert-id",
            target["id"],
            "--rules-dir",
            str(detections_dir),
            "--mock",  # explicit, even though the fixture scrubs the API key.
        ],
    )
    assert result.exit_code == 0, result.stdout
    out = json.loads(result.stdout)
    assert len(out) == 1
    assert out[0]["alert_id"] == target["id"]
    assert out[0]["verdict"] in {"true_positive", "false_positive", "needs_investigation"}
    assert 0.0 <= out[0]["confidence"] <= 1.0


def test_triage_with_unknown_alert_id_exits_1(
    tmp_data_dir: Path, detections_dir: Path
) -> None:
    _detect_alerts_json(tmp_data_dir, detections_dir)
    result = runner.invoke(
        app,
        [
            "triage",
            "--alert-id",
            "no-such-alert-id",
            "--rules-dir",
            str(detections_dir),
            "--mock",
        ],
    )
    assert result.exit_code == 1
    assert "no alert" in result.stdout.lower()


def test_triage_from_file_with_limit(
    tmp_data_dir: Path, detections_dir: Path, tmp_path: Path
) -> None:
    payload = _detect_alerts_json(tmp_data_dir, detections_dir)
    f = tmp_path / "alerts.json"
    f.write_text(payload)
    result = runner.invoke(
        app,
        ["triage", "--alert-json", str(f), "--mock", "--limit", "3"],
    )
    assert result.exit_code == 0, result.stdout
    out = json.loads(result.stdout)
    assert len(out) == 3
    for r in out:
        assert {"alert_id", "verdict", "confidence", "reasoning", "next_steps", "model"} <= r.keys()


# ---------- playbook ----------


def test_playbook_with_alert_id_renders_a_template(
    tmp_data_dir: Path, detections_dir: Path
) -> None:
    payload = _detect_alerts_json(tmp_data_dir, detections_dir)
    alerts = json.loads(payload)
    target = next(a for a in alerts if a["rule_id"] == "cdp.persistence.new_service_install")
    result = runner.invoke(
        app,
        [
            "playbook",
            "--alert-id",
            target["id"],
            "--rules-dir",
            str(detections_dir),
            "--mock",
        ],
    )
    assert result.exit_code == 0, result.stdout
    out = json.loads(result.stdout)
    assert len(out) == 1
    pb = out[0]
    assert pb["alert_id"] == target["id"]
    assert pb["model"] == "cdp-mock-playbook-v1"
    assert 5 <= len(pb["steps"]) <= 8
    assert "T1543.003" in pb["mitre_techniques"]
    # Title was rendered with the actual hostname from the matched event.
    assert "SRV-DB-01" in pb["title"]


# ---------- demo ----------


def test_demo_runs_end_to_end_with_mock(
    tmp_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`cdp demo` should ingest → detect → enrich → triage → playbook without
    touching the network, producing banners for all five phases."""
    monkeypatch.setenv("CDP_DATA_DIR", str(tmp_data_dir))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = runner.invoke(app, ["demo", "--limit", "2"])
    assert result.exit_code == 0, result.stdout
    for banner in ("1. Ingest", "2. Detect", "3. Enrich", "4. Triage", "5. Playbook", "Demo complete"):
        assert banner in result.stdout
    assert "MockTriager" in result.stdout
    assert "MockPlaybookGenerator" in result.stdout


def test_demo_falls_back_to_mock_when_claude_flag_without_key(
    tmp_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CDP_DATA_DIR", str(tmp_data_dir))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = runner.invoke(app, ["demo", "--claude", "--limit", "1"])
    assert result.exit_code == 0, result.stdout
    assert "falling back to offline mock" in result.stdout
    assert "MockTriager" in result.stdout


# ---------- serve ----------


def test_serve_invokes_uvicorn_with_cdp_api_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """`cdp serve` should hand off to uvicorn with our module-level app. We
    stub the uvicorn.run import to avoid actually binding a socket."""
    calls: list[dict] = []

    def fake_run(app_target: str, **kwargs: object) -> None:
        calls.append({"app": app_target, **kwargs})

    import uvicorn
    monkeypatch.setattr(uvicorn, "run", fake_run)

    result = runner.invoke(app, ["serve", "--host", "0.0.0.0", "--port", "9000"])
    assert result.exit_code == 0, result.stdout
    assert calls == [{
        "app": "cdp.api:app",
        "host": "0.0.0.0",
        "port": 9000,
        "reload": False,
        "log_level": "info",
    }]

