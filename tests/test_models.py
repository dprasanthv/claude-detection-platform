"""Pydantic models — validation and helper behavior."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cdp.models import Alert, SigmaRule, TriageResult


def test_sigma_rule_defaults() -> None:
    rule = SigmaRule(id="r1", title="t")
    assert rule.level == "medium"
    assert rule.status == "test"
    assert rule.tags == []
    assert rule.mitre_techniques == []


def test_mitre_techniques_extracts_uppercased_and_sorted() -> None:
    rule = SigmaRule(
        id="r1",
        title="t",
        tags=["attack.t1059.001", "attack.execution", "attack.T1078", "not.an.attack.tag"],
    )
    # Tactic tag (``attack.execution``) is excluded; technique tags survive.
    assert rule.mitre_techniques == ["T1059.001", "T1078"]


def test_severity_level_invalid_rejected() -> None:
    with pytest.raises(ValidationError):
        SigmaRule(id="r1", title="t", level="urgent")  # type: ignore[arg-type]


def test_alert_defaults_for_optional_fields() -> None:
    alert = Alert(
        id="a1",
        rule_id="r1",
        rule_title="t",
        rule_level="high",
        logsource_table="windows_process_creation",
        matched_event={"x": 1},
        matched_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert alert.rule_tags == []
    assert alert.mitre_techniques == []
    assert alert.rule_sha256 is None


def test_triage_result_confidence_must_be_in_unit_interval() -> None:
    base = {
        "alert_id": "a",
        "verdict": "true_positive",
        "reasoning": "r",
        "next_steps": ["s1"],
        "model": "mock",
    }
    with pytest.raises(ValidationError):
        TriageResult(**base, confidence=1.5)
    with pytest.raises(ValidationError):
        TriageResult(**base, confidence=-0.1)
    ok = TriageResult(**base, confidence=0.0)
    assert ok.confidence == 0.0


def test_triage_result_verdict_constrained() -> None:
    with pytest.raises(ValidationError):
        TriageResult(
            alert_id="a",
            verdict="maybe",  # type: ignore[arg-type]
            confidence=0.5,
            reasoning="r",
            next_steps=[],
            model="mock",
        )
