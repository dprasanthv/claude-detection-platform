"""Static enrichment layer.

Asserts the contract between the matched event shape (per `cdp/ingest.py`)
and the rendered :class:`Enrichment`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cdp.enrich import (
    DEFAULT_ASSET_DB,
    enrich_alert,
    enriched_for,
    load_asset_db,
)
from cdp.models import Alert


def _alert(matched_event: dict, *, rule_id: str = "test.rule", level: str = "high") -> Alert:
    return Alert(
        id=f"{rule_id}-deadbeef0000",
        rule_id=rule_id,
        rule_title="t",
        rule_level=level,  # type: ignore[arg-type]
        logsource_table="authentication",
        matched_event=matched_event,
        matched_at=datetime(2026, 4, 20, 9, 0, 0, tzinfo=UTC),
    )


# ---------- load_asset_db ----------


def test_load_asset_db_reads_repo_yaml() -> None:
    db = load_asset_db(DEFAULT_ASSET_DB)
    assert "hosts" in db
    assert "iam_users" in db
    assert "known_bad_ips" in db
    # The synthetic dataset's planted bad IP is in the DB.
    assert "185.220.101.45" in db["known_bad_ips"]


def test_load_asset_db_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_asset_db(tmp_path / "nope.yaml") == {}


def test_load_asset_db_non_mapping_raises(tmp_path: Path) -> None:
    p = tmp_path / "broken.yaml"
    p.write_text("- not\n- a\n- mapping\n")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_asset_db(p)


def test_load_asset_db_empty_file_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.yaml"
    p.write_text("")
    assert load_asset_db(p) == {}


# ---------- IP classification ----------


def test_enrich_classifies_private_ip() -> None:
    a = _alert({"source_ip": "10.0.1.15", "username": "alice"})
    e = enrich_alert(a, asset_db={})
    assert e.ip_is_private is True
    assert e.extras["ip_class"] == "private"
    assert e.ip_country is None


def test_enrich_classifies_public_ip() -> None:
    a = _alert({"source_ip": "185.220.101.45", "username": "admin"})
    e = enrich_alert(a, asset_db={})
    assert e.ip_is_private is False
    assert e.extras["ip_class"] == "public"


def test_enrich_classifies_loopback() -> None:
    a = _alert({"source_ip": "127.0.0.1"})
    e = enrich_alert(a, asset_db={})
    # Loopback addresses are technically private per ipaddress stdlib.
    assert e.ip_is_private is True
    assert e.extras["ip_class"] == "loopback"


def test_enrich_handles_invalid_ip() -> None:
    a = _alert({"source_ip": "not-an-ip"})
    e = enrich_alert(a, asset_db={})
    assert e.ip_is_private is None
    assert e.extras["ip_class"] == "invalid"


def test_enrich_handles_missing_ip_field() -> None:
    a = _alert({"username": "alice"})  # no source_ip
    e = enrich_alert(a, asset_db={})
    assert e.ip_is_private is None
    assert e.ip_country is None


def test_enrich_uses_aws_ip_field() -> None:
    a = _alert({"sourceIPAddress": "185.220.101.45", "userIdentity_userName": "dev-bob"})
    e = enrich_alert(a, asset_db={})
    assert e.ip_is_private is False


# ---------- threat-intel hit on public IP ----------


def test_enrich_attaches_threat_intel_for_known_bad_ip() -> None:
    db = {
        "known_bad_ips": {
            "185.220.101.45": {"country": "NL", "notes": "Tor exit node"},
        }
    }
    a = _alert({"source_ip": "185.220.101.45"})
    e = enrich_alert(a, asset_db=db)
    assert e.ip_country == "NL"
    assert "Tor" in e.extras["threat_intel"]


def test_enrich_does_not_apply_threat_intel_to_private_ip() -> None:
    db = {"known_bad_ips": {"10.0.0.1": {"country": "US"}}}
    a = _alert({"source_ip": "10.0.0.1"})
    e = enrich_alert(a, asset_db=db)
    # Private IPs short-circuit the TI lookup; we don't enrich them with country.
    assert e.ip_country is None


# ---------- asset DB lookup ----------


def test_enrich_resolves_host_record() -> None:
    db = {
        "hosts": {
            "SRV-DB-01": {
                "criticality": "critical",
                "owner": "data-platform@corp.example",
                "env": "production",
                "notes": "Customer DB.",
            }
        }
    }
    a = _alert({"hostname": "SRV-DB-01"})
    e = enrich_alert(a, asset_db=db)
    assert e.asset_criticality == "critical"
    assert e.asset_owner == "data-platform@corp.example"
    assert e.asset_env == "production"
    assert e.extras["asset_notes"] == "Customer DB."


def test_enrich_falls_back_to_iam_user_when_host_misses() -> None:
    db = {
        "hosts": {},
        "iam_users": {
            "dev-bob": {"criticality": "high", "owner": "bob", "env": "aws-prod"},
        },
    }
    a = _alert({"userIdentity_userName": "dev-bob"})
    e = enrich_alert(a, asset_db=db)
    assert e.asset_criticality == "high"
    assert e.asset_env == "aws-prod"


def test_enrich_unknown_host_yields_unknown_criticality() -> None:
    a = _alert({"hostname": "WKST-NEVER-HEARD-OF"})
    e = enrich_alert(a, asset_db={"hosts": {}})
    assert e.asset_criticality == "unknown"
    assert e.asset_owner is None


def test_enrich_invalid_criticality_falls_back_to_unknown() -> None:
    db = {"hosts": {"x": {"criticality": "EXTREME"}}}  # not in the literal
    a = _alert({"hostname": "x"})
    e = enrich_alert(a, asset_db=db)
    assert e.asset_criticality == "unknown"


# ---------- end-to-end against the shipped DB ----------


def test_enrich_planted_brute_force_alert_against_shipped_db() -> None:
    """Anchor: the synthetic T1110 alert (admin login from 185.220.101.45)
    must enrich to public IP + critical AUTH-SVC-01 + Tor-exit threat-intel."""
    a = _alert(
        {
            "username": "admin",
            "result": "failure",
            "source_ip": "185.220.101.45",
            "hostname": "AUTH-SVC-01",
        },
        rule_id="cdp.credential_access.brute_force_admin_login",
    )
    e = enrich_alert(a)  # uses DEFAULT_ASSET_DB
    assert e.ip_is_private is False
    assert e.ip_country == "NL"
    assert e.asset_criticality == "critical"
    assert e.asset_owner == "corp-it@corp.example"
    assert "Tor" in e.extras.get("threat_intel", "")


# ---------- enriched_for convenience ----------


def test_enriched_for_bundles_alert_enrichment_and_context() -> None:
    a = _alert({"source_ip": "10.0.0.1", "hostname": "WKST-ALICE-01"})
    bundle = enriched_for(
        a,
        context_events=[{"i": 1}, {"i": 2}],
        asset_db={"hosts": {}},
    )
    assert bundle.alert is a
    assert bundle.enrichment.alert_id == a.id
    assert len(bundle.context_events) == 2
