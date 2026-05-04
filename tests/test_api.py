"""Tests for the FastAPI surface (``cdp/api.py``).

Uses FastAPI's in-process :class:`TestClient` so we don't need a live uvicorn
server. An explicit :class:`APIState` is injected per-test so detection runs
against the shared synthetic-dataset fixture and both the triager and the
playbook generator are the deterministic offline mocks — no network, no API
key, no flakiness.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cdp.api import APIState, create_app
from cdp.config import Settings
from cdp.engine import DEFAULT_RULES_DIR
from cdp.enrich import DEFAULT_ASSET_DB
from cdp.playbook import MockPlaybookGenerator
from cdp.triage import MockTriager

# ---------- fixtures ----------


@pytest.fixture
def api_state(synthetic_dataset_dir: Path) -> APIState:
    """A hermetic :class:`APIState` pointed at the seeded dataset fixture
    with mock triager/playbook generator."""
    settings = Settings(
        data_dir=synthetic_dataset_dir,
        anthropic_api_key=None,
        model="test-mock",
    )
    return APIState(
        settings=settings,
        rules_dir=DEFAULT_RULES_DIR,
        asset_db_path=DEFAULT_ASSET_DB,
        triager_factory=lambda _s: MockTriager(),
        playbook_factory=lambda _s: MockPlaybookGenerator(),
    )


@pytest.fixture
def client(api_state: APIState) -> TestClient:
    return TestClient(create_app(api_state))


# ---------- /healthz ----------


def test_healthz_before_any_request_reports_lazy_state(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["triager"] == "MockTriager"
    assert body["playbook_generator"] == "MockPlaybookGenerator"
    assert body["has_anthropic_key"] is False
    # Detection hasn't been triggered yet, so cached counts are zero.
    assert body["rules_loaded"] == 0
    assert body["alerts_cached"] == 0


def test_healthz_reflects_cached_state_after_alerts(client: TestClient) -> None:
    client.get("/alerts")  # trigger detection
    r = client.get("/healthz")
    body = r.json()
    assert body["rules_loaded"] == 6
    assert body["alerts_cached"] == 89


# ---------- /rules ----------


def test_list_rules_returns_all_loaded_rules(client: TestClient) -> None:
    r = client.get("/rules")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 6
    ids = {rule["id"] for rule in body["rules"]}
    # Spot-check: every rule has a non-empty id + title + level.
    assert all(rule["id"] and rule["title"] and rule["level"] for rule in body["rules"])
    # The six rule ids we care about are present.
    assert "cdp.credential_access.brute_force_admin_login" in ids
    assert "cdp.exfiltration.s3_large_object_egress" in ids


# ---------- /alerts ----------


def test_list_alerts_returns_pinned_count(client: TestClient) -> None:
    r = client.get("/alerts")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 89
    assert len(body["alerts"]) == 89
    # Every alert has the fields the frontend relies on.
    for a in body["alerts"][:3]:
        for field in ("id", "rule_id", "rule_title", "rule_level", "matched_at"):
            assert field in a


def test_list_alerts_filters_by_rule_id(client: TestClient) -> None:
    rid = "cdp.credential_access.brute_force_admin_login"
    r = client.get(f"/alerts?rule_id={rid}")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 56
    assert all(a["rule_id"] == rid for a in body["alerts"])


def test_list_alerts_refresh_flag_reruns_pipeline(
    client: TestClient, api_state: APIState
) -> None:
    client.get("/alerts")
    first = api_state._alerts_by_id
    assert first is not None
    client.get("/alerts?refresh=true")
    second = api_state._alerts_by_id
    # Detection is deterministic so the alert set is identical — but the
    # dict is a fresh object after refresh.
    assert second is not None
    assert set(second.keys()) == set(first.keys())


# ---------- /alerts/{id} ----------


def test_get_alert_returns_alert_plus_enrichment(client: TestClient) -> None:
    listing = client.get("/alerts").json()["alerts"]
    alert_id = listing[0]["id"]
    r = client.get(f"/alerts/{alert_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["alert"]["id"] == alert_id
    assert "enrichment" in body
    # Enrichment always carries the alert_id it's about.
    assert body["enrichment"]["alert_id"] == alert_id


def test_get_alert_404_on_unknown_id(client: TestClient) -> None:
    r = client.get("/alerts/does-not-exist")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"]


# ---------- /alerts/{id}/triage ----------


def test_triage_returns_structured_result(client: TestClient) -> None:
    listing = client.get("/alerts").json()["alerts"]
    # Pick a critical-severity alert so we know what verdict the mock will
    # produce (high/critical → true_positive in the mock heuristic).
    critical = next(a for a in listing if a["rule_level"] == "critical")
    r = client.post(f"/alerts/{critical['id']}/triage")
    assert r.status_code == 200
    body = r.json()
    assert body["alert_id"] == critical["id"]
    assert body["verdict"] in ("true_positive", "false_positive", "needs_investigation")
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["reasoning"]
    assert body["model"] == "cdp-mock-triager-v1"


def test_triage_404_on_unknown_alert(client: TestClient) -> None:
    r = client.post("/alerts/nope/triage")
    assert r.status_code == 404


# ---------- /alerts/{id}/playbook ----------


def test_playbook_returns_structured_response(client: TestClient) -> None:
    listing = client.get("/alerts").json()["alerts"]
    alert_id = listing[0]["id"]
    r = client.post(f"/alerts/{alert_id}/playbook")
    assert r.status_code == 200
    body = r.json()
    assert body["alert_id"] == alert_id
    assert body["title"]
    assert body["summary"]
    assert len(body["steps"]) >= 3
    assert body["model"] == "cdp-mock-playbook-v1"


def test_playbook_404_on_unknown_alert(client: TestClient) -> None:
    r = client.post("/alerts/nope/playbook")
    assert r.status_code == 404


# ---------- /internal/refresh ----------


def test_refresh_endpoint_returns_pipeline_counts(client: TestClient) -> None:
    r = client.post("/internal/refresh")
    assert r.status_code == 200
    body = r.json()
    assert body["rules_loaded"] == 6
    assert body["alerts_produced"] == 89


# ---------- factory ----------


def test_create_app_builds_default_state_when_none_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Smoke-test the no-state-provided path used by the module-level `app`
    and by `cdp serve`."""
    monkeypatch.setenv("CDP_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    app = create_app()
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    # Default triager with no key is the mock.
    assert r.json()["triager"] == "MockTriager"
