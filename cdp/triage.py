"""Alert triage layer (Claude + offline mock).

Both implementations satisfy the same :class:`Triager` protocol so callers can
be written once and run hermetically (mock) or against real Claude (production).

The factory :func:`make_triager` selects implementation by inspecting
:class:`cdp.config.Settings`: a present ``ANTHROPIC_API_KEY`` selects the real
:class:`ClaudeTriager`, otherwise we fall back to :class:`MockTriager`. This
keeps tests, CI, and demos working without API credentials.
"""

from __future__ import annotations

from typing import Any, ClassVar, Protocol, cast, runtime_checkable

from cdp.config import Settings
from cdp.models import EnrichedAlert, TriageResult, TriageVerdict
from cdp.prompts import TRIAGE_SYSTEM_PROMPT, TRIAGE_TOOL, render_alert_context


@runtime_checkable
class Triager(Protocol):
    """A triager classifies an enriched alert into a :class:`TriageResult`."""

    model: str  # human-readable model id, recorded on every TriageResult.

    def triage(self, enriched: EnrichedAlert) -> TriageResult: ...


# ---------- offline mock ----------


class MockTriager:
    """Deterministic offline triager used for tests, CI, and offline demos.

    The heuristic is intentionally simple — *not* state of the art. The
    point is to provide a stable baseline for the Phase 5 eval so the
    metrics for the real Claude triager have something to compare against.

    Decision sketch:

    1. Compute a confidence floor from the rule's severity level.
    2. Bump confidence for: known-malicious keyword hit, public source IP,
       high/critical asset.
    3. Verdict:
        - keyword hit OR severity ∈ {high, critical} ⇒ ``true_positive``
        - severity == ``medium`` ⇒ ``needs_investigation``
        - severity ∈ {informational, low} ⇒ ``false_positive``
    """

    model = "cdp-mock-triager-v1"

    SEVERITY_FLOOR: ClassVar[dict[str, float]] = {
        "informational": 0.10,
        "low": 0.25,
        "medium": 0.50,
        "high": 0.70,
        "critical": 0.85,
    }

    SUSPICIOUS_KEYWORDS: ClassVar[tuple[str, ...]] = (
        "encodedcommand",
        "administratoraccess",
        "attachuserpolicy",
        "sc.exe create",
        "iex (",
        "downloadstring",
        "evil.com",
    )

    def triage(self, enriched: EnrichedAlert) -> TriageResult:
        alert = enriched.alert
        enrichment = enriched.enrichment
        haystack = str(alert.matched_event).lower()
        keyword_hits = [k for k in self.SUSPICIOUS_KEYWORDS if k in haystack]

        confidence = self.SEVERITY_FLOOR[alert.rule_level]
        if keyword_hits:
            confidence += 0.15
        if enrichment.ip_is_private is False:
            confidence += 0.05
        if enrichment.asset_criticality in ("high", "critical"):
            confidence += 0.05
        confidence = min(0.95, confidence)

        verdict: TriageVerdict
        if keyword_hits or alert.rule_level in ("high", "critical"):
            verdict = "true_positive"
        elif alert.rule_level == "medium":
            verdict = "needs_investigation"
        else:
            verdict = "false_positive"

        reasoning_parts = [
            f"Rule `{alert.rule_id}` fired at severity `{alert.rule_level}`.",
            f"MITRE: {', '.join(alert.mitre_techniques) or 'none'}.",
        ]
        if keyword_hits:
            reasoning_parts.append(
                f"Matched event contains suspicious keyword(s): {', '.join(keyword_hits)}."
            )
        if enrichment.ip_is_private is False:
            reasoning_parts.append(
                f"Source IP is public/external (country={enrichment.ip_country or 'unknown'})."
            )
        if enrichment.asset_criticality in ("high", "critical"):
            reasoning_parts.append(
                f"Affected asset has criticality `{enrichment.asset_criticality}`"
                + (f" (owner={enrichment.asset_owner})." if enrichment.asset_owner else ".")
            )

        next_steps = [
            f"Pivot on adjacent telemetry for the same actor "
            f"(host/user/IP) within ±15 minutes of {alert.matched_at.isoformat()}.",
            f"Re-run detection to confirm reproducibility: `cdp detect --rules-dir detections/ | grep {alert.rule_id}`.",
            f"Generate a containment playbook: `cdp playbook --alert-id {alert.id}`.",
        ]
        if enrichment.asset_owner:
            next_steps.append(f"Notify the asset owner: {enrichment.asset_owner}.")

        return TriageResult(
            alert_id=alert.id,
            verdict=verdict,
            confidence=round(confidence, 2),
            reasoning=" ".join(reasoning_parts),
            next_steps=next_steps[:5],  # tool schema caps at 5
            model=self.model,
        )


# ---------- real Claude ----------


class ClaudeTriager:
    """Calls Anthropic's Messages API with forced tool-use for structured output.

    Reliability comes from ``tool_choice={"type": "tool", "name": "report_triage"}``,
    which forces the model to emit a single ``tool_use`` block whose ``input``
    is validated against ``TRIAGE_TOOL["input_schema"]`` server-side. Failure
    modes:

    - The model refuses or stops with no tool block ⇒ we raise. The CLI surfaces
      this clearly so a flaky API call never silently produces a fake verdict.
    - The model emits a tool block but the JSON fails Pydantic ⇒ we let that
      ``ValidationError`` propagate. Same reasoning.
    """

    def __init__(self, *, api_key: str, model: str, max_tokens: int = 1024) -> None:
        # Defer the SDK import so importing this module is cheap (the test
        # suite imports cdp.triage even when running entirely against the mock).
        from anthropic import Anthropic

        self.model = model
        self._client = Anthropic(api_key=api_key)
        self._max_tokens = max_tokens

    def triage(self, enriched: EnrichedAlert) -> TriageResult:
        user_text = render_alert_context(enriched)
        message = self._client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            system=TRIAGE_SYSTEM_PROMPT,
            tools=[cast(Any, TRIAGE_TOOL)],
            tool_choice={"type": "tool", "name": "report_triage"},
            messages=[
                {"role": "user", "content": [{"type": "text", "text": user_text}]}
            ],
        )
        for block in message.content:
            if (
                getattr(block, "type", None) == "tool_use"
                and getattr(block, "name", None) == "report_triage"
            ):
                tool_input = cast(dict[str, Any], block.input)  # type: ignore[union-attr]
                return TriageResult(
                    alert_id=enriched.alert.id,
                    model=self.model,
                    **tool_input,
                )
        raise RuntimeError(
            "Claude did not emit a `report_triage` tool_use block "
            f"(stop_reason={message.stop_reason!r})."
        )


# ---------- factory ----------


def make_triager(settings: Settings | None = None) -> Triager:
    """Return :class:`ClaudeTriager` if ``ANTHROPIC_API_KEY`` is set, else :class:`MockTriager`."""
    cfg = settings or Settings.load()
    if cfg.has_anthropic_key:
        assert cfg.anthropic_api_key is not None  # narrowed by has_anthropic_key
        return ClaudeTriager(api_key=cfg.anthropic_api_key, model=cfg.model)
    return MockTriager()
