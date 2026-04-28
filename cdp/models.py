"""Pydantic models shared across the platform."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

TriageVerdict = Literal["true_positive", "false_positive", "needs_investigation"]
SeverityLevel = Literal["informational", "low", "medium", "high", "critical"]


class SigmaRule(BaseModel):
    """A parsed Sigma detection rule."""

    id: str
    title: str
    description: str = ""
    status: str = "test"
    level: SeverityLevel = "medium"
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, Any] = Field(default_factory=dict)
    condition: str = ""
    tags: list[str] = Field(default_factory=list)
    source_path: str | None = None
    sha256: str | None = None

    @property
    def mitre_techniques(self) -> list[str]:
        return sorted(
            tag.split(".", 1)[1].upper()
            for tag in self.tags
            if tag.lower().startswith("attack.t")
        )


class Alert(BaseModel):
    """A detection alert produced by running a Sigma rule against telemetry."""

    id: str
    rule_id: str
    rule_title: str
    rule_level: SeverityLevel
    rule_tags: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    logsource_table: str
    matched_event: dict[str, Any]
    matched_at: datetime
    rule_sha256: str | None = None


class TriageResult(BaseModel):
    """The output of the triage layer (Claude or mock)."""

    alert_id: str
    verdict: TriageVerdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    next_steps: list[str]
    model: str


class Enrichment(BaseModel):
    """Static context added to an alert before analysis."""

    alert_id: str
    ip_is_private: bool | None = None
    ip_country: str | None = None
    asset_criticality: Literal["low", "medium", "high", "critical", "unknown"] = "unknown"
    asset_owner: str | None = None
    asset_env: str | None = None
    extras: dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    """A structured incident-response playbook tailored to an alert."""

    alert_id: str
    title: str
    summary: str
    steps: list[str]
    mitre_techniques: list[str] = Field(default_factory=list)
    model: str


class EnrichedAlert(BaseModel):
    """Bundle used by downstream consumers (triage, playbook, API)."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    alert: Alert
    enrichment: Enrichment
    context_events: list[dict[str, Any]] = Field(default_factory=list)
