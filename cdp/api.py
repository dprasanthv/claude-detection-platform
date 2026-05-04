"""FastAPI surface for claude-detection-platform.

Endpoints:

- ``GET  /healthz`` — liveness + a short summary of state (rule count, alert
  count, whether the live Claude triager is wired up).
- ``GET  /rules`` — every Sigma rule currently loaded.
- ``GET  /alerts`` — every alert produced by the latest detection run. Pass
  ``?refresh=true`` to re-run ingest + detection before returning.
- ``GET  /alerts/{alert_id}`` — a single alert plus its static enrichment.
- ``POST /alerts/{alert_id}/triage`` — run the configured triager against the
  alert and return a :class:`TriageResult`. Falls back to the offline mock when
  ``ANTHROPIC_API_KEY`` is not set.
- ``POST /alerts/{alert_id}/playbook`` — same idea, for IR playbooks.

The API is deliberately *stateful but lazy*. Detection runs on first request
and the alerts are cached; ``?refresh=true`` (or POSTing to
``/internal/refresh``) re-runs the pipeline. This keeps the demo snappy after
the first hit without making the tests pay an ingest cost they can't observe.

For unit tests, construct the app with an explicit :class:`APIState` so you
can pre-seed alerts and override the triager/playbook generator without
touching environment variables.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from cdp.config import Settings
from cdp.engine import DEFAULT_RULES_DIR, DetectionEngine
from cdp.enrich import DEFAULT_ASSET_DB, enrich_alert, load_asset_db
from cdp.ingest import generate_synthetic_dataset
from cdp.models import (
    Alert,
    EnrichedAlert,
    Playbook,
    SigmaRule,
    TriageResult,
)
from cdp.playbook import PlaybookGenerator, make_playbook_generator
from cdp.store import Store
from cdp.triage import Triager, make_triager

# ---------- response envelopes ----------


class HealthResponse(BaseModel):
    status: str
    rules_loaded: int
    alerts_cached: int
    triager: str
    playbook_generator: str
    has_anthropic_key: bool


class AlertsResponse(BaseModel):
    count: int
    alerts: list[Alert]


class AlertDetailResponse(BaseModel):
    alert: Alert
    enrichment: dict[str, Any]


class RulesResponse(BaseModel):
    count: int
    rules: list[SigmaRule]


class RefreshResponse(BaseModel):
    rules_loaded: int
    alerts_produced: int


# ---------- state ----------


@dataclass
class APIState:
    """Shared, lazy state behind the API.

    Construct with sensible defaults via :func:`build_default_state`, or build
    a tailored one in tests by passing pre-loaded values to the constructor.
    """

    settings: Settings
    rules_dir: Path = DEFAULT_RULES_DIR
    asset_db_path: Path = DEFAULT_ASSET_DB
    triager_factory: Callable[[Settings], Triager] = field(
        default=lambda s: make_triager(s)
    )
    playbook_factory: Callable[[Settings], PlaybookGenerator] = field(
        default=lambda s: make_playbook_generator(s)
    )

    # Lazily-populated caches.
    _alerts_by_id: dict[str, Alert] | None = None
    _rules: list[SigmaRule] | None = None
    _asset_db: dict[str, Any] | None = None
    _triager: Triager | None = None
    _playbook: PlaybookGenerator | None = None

    # ---- accessors ----

    @property
    def triager(self) -> Triager:
        if self._triager is None:
            self._triager = self.triager_factory(self.settings)
        return self._triager

    @property
    def playbook_generator(self) -> PlaybookGenerator:
        if self._playbook is None:
            self._playbook = self.playbook_factory(self.settings)
        return self._playbook

    @property
    def asset_db(self) -> dict[str, Any]:
        if self._asset_db is None:
            self._asset_db = load_asset_db(self.asset_db_path)
        return self._asset_db

    # ---- detection pipeline ----

    def ensure_loaded(self) -> None:
        """Run ingest + detection if we haven't yet. Idempotent."""
        if self._alerts_by_id is not None:
            return
        self.refresh()

    def refresh(self) -> tuple[int, int]:
        """Re-run ingest + detection. Returns (rules_loaded, alerts_produced)."""
        data_dir = self.settings.data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        generate_synthetic_dataset(data_dir)

        with Store(data_dir=data_dir) as store:
            store.load_all()
            engine = DetectionEngine(store, rules_dir=self.rules_dir)
            engine.load_rules()
            alerts = engine.run_all()
            self._rules = list(engine.rules)

        self._alerts_by_id = {a.id: a for a in alerts}
        return len(self._rules), len(self._alerts_by_id)

    # ---- queries ----

    def alerts(self) -> list[Alert]:
        self.ensure_loaded()
        assert self._alerts_by_id is not None
        return list(self._alerts_by_id.values())

    def get_alert(self, alert_id: str) -> Alert:
        self.ensure_loaded()
        assert self._alerts_by_id is not None
        if alert_id not in self._alerts_by_id:
            raise KeyError(alert_id)
        return self._alerts_by_id[alert_id]

    def rules(self) -> list[SigmaRule]:
        self.ensure_loaded()
        assert self._rules is not None
        return list(self._rules)

    def enrich(self, alert: Alert) -> EnrichedAlert:
        return EnrichedAlert(alert=alert, enrichment=enrich_alert(alert, self.asset_db))


def build_default_state() -> APIState:
    """Build an :class:`APIState` from environment-loaded :class:`Settings`."""
    return APIState(settings=Settings.load())


# ---------- app factory ----------


def create_app(state: APIState | None = None) -> FastAPI:
    """Construct the FastAPI app. Pass ``state`` in tests to inject a
    pre-loaded / mocked-out :class:`APIState`; production callers (the
    ``cdp serve`` CLI) leave it unset to get the env-driven default."""
    api_state = state if state is not None else build_default_state()

    app = FastAPI(
        title="Claude Detection Platform",
        version="0.1.0",
        description=(
            "Sigma-based detection-as-code platform with Claude-powered "
            "alert triage and response playbooks."
        ),
    )
    app.state.cdp = api_state  # exposed for tests / introspection.

    @app.get("/healthz", response_model=HealthResponse, tags=["meta"])
    def healthz() -> HealthResponse:
        # Cheap path: don't trigger detection just to answer the healthcheck.
        rules = api_state._rules or []
        alerts = api_state._alerts_by_id or {}
        return HealthResponse(
            status="ok",
            rules_loaded=len(rules),
            alerts_cached=len(alerts),
            triager=type(api_state.triager).__name__,
            playbook_generator=type(api_state.playbook_generator).__name__,
            has_anthropic_key=api_state.settings.has_anthropic_key,
        )

    @app.get("/rules", response_model=RulesResponse, tags=["rules"])
    def list_rules() -> RulesResponse:
        rules = api_state.rules()
        return RulesResponse(count=len(rules), rules=rules)

    @app.get("/alerts", response_model=AlertsResponse, tags=["alerts"])
    def list_alerts(
        refresh: bool = Query(False, description="Re-run ingest + detection before returning."),
        rule_id: str | None = Query(None, description="Filter to alerts from a specific rule."),
    ) -> AlertsResponse:
        if refresh:
            api_state.refresh()
        alerts = api_state.alerts()
        if rule_id is not None:
            alerts = [a for a in alerts if a.rule_id == rule_id]
        return AlertsResponse(count=len(alerts), alerts=alerts)

    @app.get("/alerts/{alert_id}", response_model=AlertDetailResponse, tags=["alerts"])
    def get_alert(alert_id: str) -> AlertDetailResponse:
        try:
            alert = api_state.get_alert(alert_id)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=f"alert {alert_id!r} not found") from e
        enriched = api_state.enrich(alert)
        return AlertDetailResponse(
            alert=enriched.alert,
            enrichment=enriched.enrichment.model_dump(mode="json"),
        )

    @app.post(
        "/alerts/{alert_id}/triage",
        response_model=TriageResult,
        tags=["alerts"],
    )
    def triage_alert(alert_id: str) -> TriageResult:
        try:
            alert = api_state.get_alert(alert_id)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=f"alert {alert_id!r} not found") from e
        enriched = api_state.enrich(alert)
        return api_state.triager.triage(enriched)

    @app.post(
        "/alerts/{alert_id}/playbook",
        response_model=Playbook,
        tags=["alerts"],
    )
    def playbook_for_alert(alert_id: str) -> Playbook:
        try:
            alert = api_state.get_alert(alert_id)
        except KeyError as e:
            raise HTTPException(status_code=404, detail=f"alert {alert_id!r} not found") from e
        enriched = api_state.enrich(alert)
        return api_state.playbook_generator.generate(enriched)

    @app.post("/internal/refresh", response_model=RefreshResponse, tags=["meta"])
    def refresh_pipeline() -> RefreshResponse:
        rules_loaded, alerts_produced = api_state.refresh()
        return RefreshResponse(rules_loaded=rules_loaded, alerts_produced=alerts_produced)

    return app


# Module-level app instance for `uvicorn cdp.api:app` and for the
# `cdp serve` subcommand. Built lazily-ish: import-time construction is
# fine because no detection runs until the first request.
app = create_app()
