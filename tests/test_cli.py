"""Typer CLI smoke tests using Click's :class:`CliRunner`.

These tests run the CLI in-process (no subprocess), so they're fast and
exercise the same code paths a user would hit at the terminal.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    for cmd in ("ingest", "detect", "validate", "version"):
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
