"""Prompt + tool-schema invariants for the Claude AI layer.

We pin the rendered alert format so prompt drift is a deliberate code change
(visible in git) rather than an accidental side-effect.
"""

from __future__ import annotations

from datetime import UTC, datetime

from cdp.models import Alert, EnrichedAlert, Enrichment
from cdp.prompts import (
    PLAYBOOK_SYSTEM_PROMPT,
    PLAYBOOK_TOOL,
    TRIAGE_SYSTEM_PROMPT,
    TRIAGE_TOOL,
    render_alert_context,
)


def _make_enriched(
    *,
    matched_event: dict | None = None,
    enrichment: Enrichment | None = None,
    context_events: list[dict] | None = None,
) -> EnrichedAlert:
    alert = Alert(
        id="cdp.execution.powershell_encoded_command-abcdef012345",
        rule_id="cdp.execution.powershell_encoded_command",
        rule_title="PowerShell EncodedCommand Invocation",
        rule_level="high",
        rule_tags=["attack.execution", "attack.t1059.001"],
        mitre_techniques=["T1059.001"],
        logsource_table="windows_process_creation",
        matched_event=matched_event or {"Image": "powershell.exe", "User": "alice"},
        matched_at=datetime(2026, 4, 20, 9, 17, 0, tzinfo=UTC),
        rule_sha256="0" * 64,
    )
    enrich = enrichment or Enrichment(
        alert_id=alert.id,
        ip_is_private=False,
        ip_country="NL",
        asset_criticality="medium",
        asset_owner="alice@corp.example",
        asset_env="corporate",
        extras={"ip": "185.220.101.45", "ip_class": "public"},
    )
    return EnrichedAlert(alert=alert, enrichment=enrich, context_events=context_events or [])


# ---------- system prompt invariants ----------


def test_triage_system_prompt_mentions_required_fields() -> None:
    for token in ("verdict", "confidence", "reasoning", "next_steps", "report_triage"):
        assert token in TRIAGE_SYSTEM_PROMPT, f"missing token: {token}"


def test_triage_system_prompt_warns_against_prompt_injection() -> None:
    # Defense-in-depth: the system prompt must explicitly tell Claude to treat
    # the matched-event content as data, not instructions.
    assert "untrusted data" in TRIAGE_SYSTEM_PROMPT.lower()


def test_playbook_system_prompt_mentions_required_fields() -> None:
    for token in ("title", "summary", "steps", "submit_playbook"):
        assert token in PLAYBOOK_SYSTEM_PROMPT


def test_playbook_system_prompt_warns_against_prompt_injection() -> None:
    assert "untrusted data" in PLAYBOOK_SYSTEM_PROMPT.lower()


# ---------- tool schema invariants ----------


def test_triage_tool_schema_shape() -> None:
    schema = TRIAGE_TOOL["input_schema"]
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"verdict", "confidence", "reasoning", "next_steps"}
    verdict_enum = schema["properties"]["verdict"]["enum"]
    assert set(verdict_enum) == {"true_positive", "false_positive", "needs_investigation"}
    assert schema["properties"]["confidence"]["minimum"] == 0.0
    assert schema["properties"]["confidence"]["maximum"] == 1.0
    assert schema["properties"]["next_steps"]["minItems"] == 3
    assert schema["properties"]["next_steps"]["maxItems"] == 5


def test_playbook_tool_schema_shape() -> None:
    schema = PLAYBOOK_TOOL["input_schema"]
    assert schema["type"] == "object"
    assert set(schema["required"]) == {"title", "summary", "steps"}
    assert schema["properties"]["steps"]["minItems"] == 5
    assert schema["properties"]["steps"]["maxItems"] == 8


# ---------- render_alert_context ----------


def test_render_alert_context_has_all_sections() -> None:
    out = render_alert_context(_make_enriched())
    for section in ("ALERT", "MATCHED EVENT", "ENRICHMENT"):
        assert section in out


def test_render_alert_context_includes_alert_metadata() -> None:
    out = render_alert_context(_make_enriched())
    assert "cdp.execution.powershell_encoded_command" in out
    assert "T1059.001" in out
    assert "windows_process_creation" in out
    assert "high" in out
    # Matched_at is rendered in ISO 8601 with timezone.
    assert "2026-04-20T09:17:00+00:00" in out


def test_render_alert_context_renders_enrichment_fields() -> None:
    out = render_alert_context(_make_enriched())
    assert "ip_is_private:     False" in out
    assert "ip_country:        NL" in out
    assert "asset_criticality: medium" in out
    assert "asset_owner:       alice@corp.example" in out


def test_render_alert_context_renders_unknown_country_as_unknown() -> None:
    enrichment = Enrichment(
        alert_id="x",
        ip_is_private=True,
        ip_country=None,
        asset_criticality="unknown",
    )
    out = render_alert_context(_make_enriched(enrichment=enrichment))
    assert "ip_country:        (unknown)" in out


def test_render_alert_context_includes_context_events_when_present() -> None:
    out = render_alert_context(
        _make_enriched(
            context_events=[
                {"timestamp": "2026-04-20T09:16:00Z", "evt": "before"},
                {"timestamp": "2026-04-20T09:18:00Z", "evt": "after"},
            ]
        )
    )
    assert "CONTEXT EVENTS (2 of 2 shown)" in out
    assert "before" in out
    assert "after" in out


def test_render_alert_context_omits_context_section_when_empty() -> None:
    out = render_alert_context(_make_enriched())
    assert "CONTEXT EVENTS" not in out


def test_render_alert_context_truncates_to_max_context_events() -> None:
    events = [{"i": i} for i in range(10)]
    out = render_alert_context(_make_enriched(context_events=events), max_context_events=3)
    assert "CONTEXT EVENTS (3 of 10 shown)" in out
