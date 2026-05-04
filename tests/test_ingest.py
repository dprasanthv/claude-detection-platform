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
    # 3 * 150 benign + planted attacks (3 windows + 50 auth + 26 aws) +
    # FP-shape benign-but-rule-firing events (6 auth + 3 aws). See
    # `_benign_but_rule_firing_*` in `cdp/ingest.py`.
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
    # 25 attack (acme-customer-pii from the Tor IP) + 3 FP-shape (acme-analytics-exports
    # from an internal IP) — both fire the rule, eval ground truth distinguishes them.
    assert n == 28


def test_admin_failures_from_external_ips_are_only_attack_or_fp_burst(
    synthetic_dataset_dir: Path,
) -> None:
    """The brute-force rule's ``not internal_ranges`` filter relies on this:
    every benign admin failure that *isn't* part of either planted scenario
    (50-event Tor burst or 6-event coffee-shop burst) must come from a
    10./192.168./172.16. IP."""
    n = _count(
        synthetic_dataset_dir / "authentication.parquet",
        "username='admin' AND result='failure' "
        "AND NOT (source_ip LIKE '10.%' "
        "OR source_ip LIKE '192.168.%' "
        "OR source_ip LIKE '172.16.%')",
    )
    # 50 TP attack burst (185.220.101.45) + 6 FP burst (198.51.100.10).
    assert n == 56


# ---------- FP-shape benign-but-rule-firing events ----------


def test_benign_but_rule_firing_admin_failures_from_legit_external_ip(
    synthetic_dataset_dir: Path,
) -> None:
    """6 admin failures from public-but-legitimate IP 198.51.100.10 (coffee-shop
    network), followed by a successful login — the brute-force rule fires,
    but ground truth labels these failures FP. Phase 5 eval signal."""
    failures = _count(
        synthetic_dataset_dir / "authentication.parquet",
        "username='admin' AND result='failure' AND source_ip='198.51.100.10'",
    )
    assert failures == 6
    successes = _count(
        synthetic_dataset_dir / "authentication.parquet",
        "username='admin' AND result='success' AND source_ip='198.51.100.10'",
    )
    assert successes == 1, "the 'got it on the 7th try' disambiguation signal"


def test_benign_but_rule_firing_s3_egress_from_internal_ip(
    synthetic_dataset_dir: Path,
) -> None:
    """3 large S3 GetObjects from internal IP 10.0.5.12 by dev-alice into the
    analytics-exports bucket — the s3-egress rule fires, but ground truth
    labels them FP. Phase 5 eval signal."""
    n = _count(
        synthetic_dataset_dir / "aws_cloudtrail.parquet",
        "eventName='GetObject' AND bytes_out > 50000000 "
        "AND sourceIPAddress='10.0.5.12' AND userIdentity_userName='dev-alice'",
    )
    assert n == 3


# ---------- mordor extension point ----------


def test_load_mordor_raises_not_implemented(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError):
        load_mordor("apt29-day1", tmp_path)
