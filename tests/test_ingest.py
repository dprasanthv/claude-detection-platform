"""Synthetic ingest — determinism and planted-attack invariants.

These tests are the contract between ``ingest.py`` and every downstream phase
(rules, evals, ground-truth labels). If a change here flips the assertions,
the eval ground truth and per-rule expected counts must move with it.
"""

from __future__ import annotations

import json
from pathlib import Path

import duckdb
import pytest

from cdp.ingest import generate_synthetic_dataset, load_mordor

# ---------- shape + determinism ----------


def test_generate_synthetic_creates_three_tables(tmp_path: Path) -> None:
    stats = generate_synthetic_dataset(tmp_path)
    assert set(stats.per_table) == {
        "windows_process_creation",
        "authentication",
        "aws_cloudtrail",
    }
    for name in stats.per_table:
        assert (tmp_path / f"{name}.parquet").exists()
        assert (tmp_path / f"{name}.jsonl").exists()
    assert stats.total_events == sum(stats.per_table.values())
    # 3 * 150 benign + planted attacks (3 windows + 50 auth + 26 aws).
    assert stats.total_events > 500


def test_generate_synthetic_is_deterministic(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    generate_synthetic_dataset(a)
    generate_synthetic_dataset(b)
    for name in ("windows_process_creation", "authentication", "aws_cloudtrail"):
        # Byte-for-byte JSONL equality is the strictest determinism check.
        assert (a / f"{name}.jsonl").read_bytes() == (b / f"{name}.jsonl").read_bytes()


def test_generate_synthetic_jsonl_is_valid_ndjson(tmp_path: Path) -> None:
    generate_synthetic_dataset(tmp_path)
    for jsonl in tmp_path.glob("*.jsonl"):
        for line in jsonl.read_text().splitlines():
            json.loads(line)


# ---------- planted-attack invariants ----------


def _count(parquet: Path, where: str) -> int:
    con = duckdb.connect(":memory:")
    try:
        safe_path = str(parquet).replace("'", "''")
        row = con.execute(
            f"SELECT count(*) FROM read_parquet('{safe_path}') WHERE {where}"
        ).fetchone()
    finally:
        con.close()
    assert row is not None
    return int(row[0])


def test_planted_t1110_brute_force_admin_failures(synthetic_dataset_dir: Path) -> None:
    n = _count(
        synthetic_dataset_dir / "authentication.parquet",
        "username='admin' AND result='failure' AND source_ip='185.220.101.45'",
    )
    assert n == 50, "T1110 plant must be exactly 50 admin failures from the public IP"


def test_planted_t1059_001_powershell_encoded_command(synthetic_dataset_dir: Path) -> None:
    n = _count(
        synthetic_dataset_dir / "windows_process_creation.parquet",
        "CommandLine LIKE '%-EncodedCommand%'",
    )
    assert n == 1


def test_planted_t1543_003_new_service_install(synthetic_dataset_dir: Path) -> None:
    # Image ends with `\sc.exe` and command line contains ` create `.
    n = _count(
        synthetic_dataset_dir / "windows_process_creation.parquet",
        "Image LIKE '%sc.exe' AND CommandLine LIKE '% create %'",
    )
    assert n == 1


def test_planted_t1078_iam_admin_attach(synthetic_dataset_dir: Path) -> None:
    n = _count(
        synthetic_dataset_dir / "aws_cloudtrail.parquet",
        "eventName='AttachUserPolicy' "
        "AND requestParameters LIKE '%AdministratorAccess%'",
    )
    assert n == 1


def test_planted_t1567_002_s3_egress_burst(synthetic_dataset_dir: Path) -> None:
    n = _count(
        synthetic_dataset_dir / "aws_cloudtrail.parquet",
        "eventName='GetObject' AND eventSource='s3.amazonaws.com' AND bytes_out > 50000000",
    )
    assert n == 25


def test_no_benign_admin_failures_from_external_ips(synthetic_dataset_dir: Path) -> None:
    """The brute-force rule's ``not internal_ranges`` filter relies on this:
    every benign admin failure must come from a 10./192.168./172.16. IP."""
    n = _count(
        synthetic_dataset_dir / "authentication.parquet",
        "username='admin' AND result='failure' "
        "AND NOT (source_ip LIKE '10.%' "
        "OR source_ip LIKE '192.168.%' "
        "OR source_ip LIKE '172.16.%')",
    )
    assert n == 50, "only the 50 planted brute-force events should match"


# ---------- mordor extension point ----------


def test_load_mordor_raises_not_implemented(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError):
        load_mordor("apt29-day1", tmp_path)
