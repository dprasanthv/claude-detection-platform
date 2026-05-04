"""Triage layer — :class:`MockTriager` matrix and :class:`ClaudeTriager` plumbing.

The Claude tests use a stub SDK so we don't need a real API key (and don't
make network calls). The mock tests pin the deterministic heuristic so it's
a stable baseline for the Phase 5 eval.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import patch

import pytest

from cdp.config import Settings
from cdp.models import Alert, EnrichedAlert, Enrichment, TriageResult
from cdp.triage import ClaudeTriager, MockTriager, Triager, make_triager


def _alert(rule_level: str, *, rule_id: str = "test.rule", matched_event: dict | None = None) -> Alert:
    return Alert(
        id=f"{rule_id}-deadbeef0000",
        rule_id=rule_id,
        rule_title="t",
        rule_level=rule_level,  # type: ignore[arg-type]
        rule_tags=["attack.execution", "attack.t1059.001"],
        mitre_techniques=["T1059.001"],
        logsource_table="windows_process_creation",
        matched_event=matched_event or {},
        matched_at=datetime(2026, 4, 20, 9, 0, 0, tzinfo=UTC),
    )


def _enrich(
    alert_id: str,
    *,
    ip_is_private: bool | None = None,
    asset_criticality: str = "unknown",
    asset_owner: str | None = None,
) -> Enrichment:
    return Enrichment(
        alert_id=alert_id,
        ip_is_private=ip_is_private,
        asset_criticality=asset_criticality,  # type: ignore[arg-type]
        asset_owner=asset_owner,
    )


def _bundle(alert: Alert, enrichment: Enrichment | None = None) -> EnrichedAlert:
    return EnrichedAlert(alert=alert, enrichment=enrichment or _enrich(alert.id))


# ---------- protocol conformance ----------


def test_mock_triager_satisfies_triager_protocol() -> None:
    assert isinstance(MockTriager(), Triager)


def test_mock_triager_returns_valid_triage_result() -> None:
    res = MockTriager().triage(_bundle(_alert("high")))
    assert isinstance(res, TriageResult)
    assert 0.0 <= res.confidence <= 1.0
    assert 3 <= len(res.next_steps) <= 5  # tool schema bounds
    assert res.model == "cdp-mock-triager-v1"


# ---------- verdict matrix ----------


@pytest.mark.parametrize(
    ("rule_level", "expected_verdict"),
    [
        ("informational", "false_positive"),
        ("low", "false_positive"),
        ("medium", "needs_investigation"),
        ("high", "true_positive"),
        ("critical", "true_positive"),
    ],
)
def test_mock_triager_verdict_by_severity(rule_level: str, expected_verdict: str) -> None:
    res = MockTriager().triage(_bundle(_alert(rule_level)))
    assert res.verdict == expected_verdict


def test_mock_triager_keyword_hit_forces_true_positive_even_for_low_severity() -> None:
    alert = _alert(
        "low",
        matched_event={"CommandLine": "powershell.exe -EncodedCommand AAAA"},
    )
    res = MockTriager().triage(_bundle(alert))
    assert res.verdict == "true_positive"
    assert "encodedcommand" in res.reasoning.lower()


def test_mock_triager_confidence_increases_with_signals() -> None:
    base = MockTriager().triage(_bundle(_alert("high"))).confidence
    boosted = MockTriager().triage(
        _bundle(
            _alert("high", matched_event={"x": "AdministratorAccess"}),
            _enrich("test.rule-deadbeef0000", ip_is_private=False, asset_criticality="critical"),
        )
    ).confidence
    assert boosted > base


def test_mock_triager_confidence_capped_at_0_95() -> None:
    res = MockTriager().triage(
        _bundle(
            _alert("critical", matched_event={"x": "EncodedCommand AdministratorAccess sc.exe create"}),
            _enrich("test.rule-deadbeef0000", ip_is_private=False, asset_criticality="critical"),
        )
    )
    assert res.confidence <= 0.95


# ---------- determinism ----------


def test_mock_triager_is_deterministic() -> None:
    """Same input ⇒ identical TriageResult across two invocations."""
    alert = _alert("high", matched_event={"CommandLine": "powershell.exe -EncodedCommand AAAA"})
    a = MockTriager().triage(_bundle(alert))
    b = MockTriager().triage(_bundle(alert))
    assert a == b


# ---------- ClaudeTriager via stubbed SDK ----------


class _StubAnthropicSDK:
    """Tiny stand-in for the Anthropic Python SDK.

    Captures the create() args so we can inspect them, and returns a canned
    response that yields a tool_use block for the report_triage tool.
    """

    last_create_kwargs: ClassVar[dict[str, Any]] = {}

    @classmethod
    def Anthropic(cls, *, api_key: str) -> Any:
        return cls._Client()

    class _Client:
        def __init__(self) -> None:
            self.messages = _StubAnthropicSDK._Messages()

    class _Messages:
        def create(self, **kwargs: Any) -> Any:
            _StubAnthropicSDK.last_create_kwargs = kwargs
            tool_block = SimpleNamespace(
                type="tool_use",
                name="report_triage",
                input={
                    "verdict": "true_positive",
                    "confidence": 0.92,
                    "reasoning": "Encoded PowerShell from a public IP.",
                    "next_steps": [
                        "Decode the EncodedCommand payload offline.",
                        "Isolate the host pending forensics.",
                        "Reset the user's credentials.",
                    ],
                },
            )
            return SimpleNamespace(content=[tool_block], stop_reason="tool_use")


def test_claude_triager_extracts_tool_use_block() -> None:
    with patch.dict("sys.modules", {"anthropic": _StubAnthropicSDK}):
        triager = ClaudeTriager(api_key="sk-test", model="claude-sonnet-4-5")
        res = triager.triage(_bundle(_alert("high")))
    assert res.verdict == "true_positive"
    assert res.confidence == 0.92
    assert res.model == "claude-sonnet-4-5"
    # The user-facing prompt was rendered and forwarded.
    msg = _StubAnthropicSDK.last_create_kwargs["messages"][0]
    assert msg["role"] == "user"
    user_text = msg["content"][0]["text"]
    assert "ALERT" in user_text and "MATCHED EVENT" in user_text
    # Forced tool-use was set.
    tc = _StubAnthropicSDK.last_create_kwargs["tool_choice"]
    assert tc == {"type": "tool", "name": "report_triage"}


class _StubNoToolBlockSDK(_StubAnthropicSDK):
    """SDK stub that returns a stop_reason='end_turn' with no tool_use block."""

    class _Messages:  # type: ignore[misc]
        def create(self, **_: Any) -> Any:
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text="I refuse.")],
                stop_reason="end_turn",
            )

    class _Client:  # type: ignore[misc]
        def __init__(self) -> None:
            self.messages = _StubNoToolBlockSDK._Messages()

    @classmethod
    def Anthropic(cls, *, api_key: str) -> Any:
        return cls._Client()


def test_claude_triager_raises_when_no_tool_use_block() -> None:
    with patch.dict("sys.modules", {"anthropic": _StubNoToolBlockSDK}):
        triager = ClaudeTriager(api_key="sk-test", model="claude-sonnet-4-5")
        with pytest.raises(RuntimeError, match="report_triage"):
            triager.triage(_bundle(_alert("high")))


# ---------- factory ----------


def test_make_triager_returns_mock_when_no_api_key() -> None:
    cfg = Settings(data_dir=__import__("pathlib").Path("/tmp"), anthropic_api_key=None, model="m")
    assert isinstance(make_triager(cfg), MockTriager)


def test_make_triager_returns_claude_when_key_set() -> None:
    cfg = Settings(data_dir=__import__("pathlib").Path("/tmp"), anthropic_api_key="sk-test", model="m")
    with patch.dict("sys.modules", {"anthropic": _StubAnthropicSDK}):
        triager = make_triager(cfg)
    assert isinstance(triager, ClaudeTriager)
    assert triager.model == "m"
