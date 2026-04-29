"""Playbook layer — :class:`MockPlaybookGenerator` templates and Claude plumbing."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import patch

import pytest

from cdp.config import Settings
from cdp.models import Alert, EnrichedAlert, Enrichment, Playbook
from cdp.playbook import (
    _GENERIC_TEMPLATE,
    _TEMPLATES,
    ClaudePlaybookGenerator,
    MockPlaybookGenerator,
    PlaybookGenerator,
    make_playbook_generator,
)

SHIPPED_RULE_IDS = {
    "cdp.credential_access.brute_force_admin_login",
    "cdp.credential_access.iam_admin_policy_attached",
    "cdp.execution.powershell_encoded_command",
    "cdp.execution.office_spawns_script_host",
    "cdp.persistence.new_service_install",
    "cdp.exfiltration.s3_large_object_egress",
}

_PLACEHOLDER_RE = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


def _alert(
    rule_id: str,
    *,
    matched_event: dict | None = None,
    level: str = "high",
    mitre: list[str] | None = None,
) -> Alert:
    return Alert(
        id=f"{rule_id}-deadbeef0000",
        rule_id=rule_id,
        rule_title="t",
        rule_level=level,  # type: ignore[arg-type]
        rule_tags=["attack.execution", "attack.t1059.001"],
        mitre_techniques=mitre or ["T1059.001"],
        logsource_table="windows_process_creation",
        matched_event=matched_event or {},
        matched_at=datetime(2026, 4, 20, 9, 0, 0, tzinfo=UTC),
    )


def _bundle(alert: Alert) -> EnrichedAlert:
    return EnrichedAlert(
        alert=alert,
        enrichment=Enrichment(
            alert_id=alert.id,
            ip_is_private=False,
            asset_criticality="high",
            asset_owner="alice@corp.example",
        ),
    )


# ---------- protocol conformance ----------


def test_mock_generator_satisfies_protocol() -> None:
    assert isinstance(MockPlaybookGenerator(), PlaybookGenerator)


# ---------- template coverage ----------


def test_every_shipped_rule_has_a_dedicated_template() -> None:
    """Each Sigma rule shipped in the repo gets a tailored playbook template."""
    assert set(_TEMPLATES) >= SHIPPED_RULE_IDS, (
        f"missing templates for: {SHIPPED_RULE_IDS - set(_TEMPLATES)}"
    )


def test_each_template_has_5_to_8_steps() -> None:
    for rule_id, tpl in _TEMPLATES.items():
        n = len(tpl["steps"])
        assert 5 <= n <= 8, f"{rule_id} has {n} steps (must be 5-8)"


def test_generic_template_has_5_to_8_steps() -> None:
    n = len(_GENERIC_TEMPLATE["steps"])
    assert 5 <= n <= 8


# ---------- mock generator: rendering ----------


def _generate(rule_id: str, matched_event: dict | None = None) -> Playbook:
    alert = _alert(rule_id, matched_event=matched_event)
    return MockPlaybookGenerator().generate(_bundle(alert))


def _no_unfilled_placeholders(text: str) -> bool:
    return _PLACEHOLDER_RE.search(text) is None


@pytest.mark.parametrize("rule_id", sorted(SHIPPED_RULE_IDS))
def test_mock_generator_renders_each_shipped_rule_without_unfilled_placeholders(
    rule_id: str,
) -> None:
    """Every per-rule template, fed a representative event, fills all its placeholders."""
    matched_events = {
        "cdp.credential_access.brute_force_admin_login": {
            "username": "admin",
            "source_ip": "185.220.101.45",
            "hostname": "AUTH-SVC-01",
        },
        "cdp.credential_access.iam_admin_policy_attached": {
            "userIdentity_userName": "dev-bob",
            "sourceIPAddress": "185.220.101.45",
        },
        "cdp.execution.powershell_encoded_command": {
            "Image": r"C:\Windows\System32\powershell.exe",
            "ParentImage": r"...\WINWORD.EXE",
            "User": "alice",
            "hostname": "WKST-ALICE-01",
        },
        "cdp.execution.office_spawns_script_host": {
            "Image": r"C:\Windows\System32\powershell.exe",
            "ParentImage": r"...\WINWORD.EXE",
            "ParentCommandLine": r'"WINWORD.EXE" /n "invoice.docx"',
            "User": "bob",
            "hostname": "WKST-BOB-02",
        },
        "cdp.persistence.new_service_install": {
            "Image": r"C:\Windows\System32\sc.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "User": "svc_sql",
            "hostname": "SRV-DB-01",
        },
        "cdp.exfiltration.s3_large_object_egress": {
            "userIdentity_userName": "dev-bob",
            "sourceIPAddress": "185.220.101.45",
        },
    }
    pb = _generate(rule_id, matched_events[rule_id])
    assert _no_unfilled_placeholders(pb.title), f"unfilled placeholder in title: {pb.title}"
    assert _no_unfilled_placeholders(pb.summary), f"unfilled placeholder in summary: {pb.summary}"
    for step in pb.steps:
        assert _no_unfilled_placeholders(step), f"unfilled placeholder in step: {step}"


def test_mock_generator_propagates_mitre_techniques() -> None:
    pb = _generate(
        "cdp.execution.powershell_encoded_command",
        {"Image": "powershell.exe", "User": "alice", "hostname": "WKST-ALICE-01"},
    )
    assert pb.mitre_techniques == ["T1059.001"]


def test_mock_generator_uses_alert_id_as_pb_id() -> None:
    pb = _generate("cdp.persistence.new_service_install", {"hostname": "SRV-DB-01"})
    assert pb.alert_id.endswith("deadbeef0000")
    assert pb.model == "cdp-mock-playbook-v1"


def test_mock_generator_falls_back_to_generic_template_for_unknown_rule() -> None:
    pb = _generate("unknown.rule.id", {})
    assert pb.alert_id.endswith("deadbeef0000")
    # Generic template references the rule id and severity; both must be filled.
    assert "unknown.rule.id" in pb.summary
    assert _no_unfilled_placeholders(pb.summary)
    for step in pb.steps:
        assert _no_unfilled_placeholders(step)


def test_mock_generator_handles_missing_event_fields_gracefully() -> None:
    """A bare event with no host/user/IP must still produce a playbook with no
    crashes — placeholders fall back to ``(unknown ...)`` strings."""
    pb = _generate("cdp.persistence.new_service_install", matched_event={})
    for step in pb.steps:
        assert _no_unfilled_placeholders(step)
    assert "unknown" in (pb.title + pb.summary).lower()


def test_mock_generator_is_deterministic() -> None:
    a = _generate("cdp.persistence.new_service_install", {"hostname": "SRV-DB-01"})
    b = _generate("cdp.persistence.new_service_install", {"hostname": "SRV-DB-01"})
    assert a == b


# ---------- ClaudePlaybookGenerator via stubbed SDK ----------


class _StubAnthropicSDK:
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
                name="submit_playbook",
                input={
                    "title": "Contain encoded PowerShell on WKST-ALICE-01",
                    "summary": "Suspicious encoded PS payload from a public IP.",
                    "steps": [
                        "Decode payload offline.",
                        "Isolate WKST-ALICE-01 from the network.",
                        "Pull the EDR process tree.",
                        "Reset alice's credentials.",
                        "Open IR ticket and notify owner.",
                    ],
                },
            )
            return SimpleNamespace(content=[tool_block], stop_reason="tool_use")


def test_claude_generator_extracts_tool_use_block() -> None:
    alert = _alert("cdp.execution.powershell_encoded_command", matched_event={"x": 1})
    with patch.dict("sys.modules", {"anthropic": _StubAnthropicSDK}):
        gen = ClaudePlaybookGenerator(api_key="sk-test", model="claude-sonnet-4-5")
        pb = gen.generate(_bundle(alert))
    assert pb.title.startswith("Contain")
    assert len(pb.steps) == 5
    assert pb.model == "claude-sonnet-4-5"
    assert pb.mitre_techniques == ["T1059.001"]
    tc = _StubAnthropicSDK.last_create_kwargs["tool_choice"]
    assert tc == {"type": "tool", "name": "submit_playbook"}


# ---------- factory ----------


def test_make_playbook_generator_returns_mock_when_no_key() -> None:
    cfg = Settings(data_dir=Path("/tmp"), anthropic_api_key=None, model="m")
    assert isinstance(make_playbook_generator(cfg), MockPlaybookGenerator)


def test_make_playbook_generator_returns_claude_when_key_set() -> None:
    cfg = Settings(data_dir=Path("/tmp"), anthropic_api_key="sk-test", model="m")
    with patch.dict("sys.modules", {"anthropic": _StubAnthropicSDK}):
        gen = make_playbook_generator(cfg)
    assert isinstance(gen, ClaudePlaybookGenerator)
    assert gen.model == "m"
