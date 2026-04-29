"""IR playbook generation (Claude + offline mock).

Mirrors ``cdp.triage``: a :class:`PlaybookGenerator` protocol, a deterministic
:class:`MockPlaybookGenerator` for hermetic runs, and a :class:`ClaudePlaybookGenerator`
that uses the Anthropic SDK with forced tool-use.

The mock is templated per-rule. Each shipped Sigma rule has its own template
keyed by ``rule_id``; rules without a template fall back to a generic
container/investigation skeleton.
"""

from __future__ import annotations

from typing import Any, Protocol, cast, runtime_checkable

from cdp.config import Settings
from cdp.models import EnrichedAlert, Playbook
from cdp.prompts import PLAYBOOK_SYSTEM_PROMPT, PLAYBOOK_TOOL, render_alert_context


@runtime_checkable
class PlaybookGenerator(Protocol):
    model: str

    def generate(self, enriched: EnrichedAlert) -> Playbook: ...


# ---------- offline mock ----------


class _SafeFormatDict(dict[str, str]):
    """A dict that returns ``"{key}"`` for missing keys instead of raising.

    Lets us call ``str.format_map`` on templates without worrying about
    every possible event shape having every placeholder.
    """

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


# Per-rule templates. Each template's strings are rendered through
# ``str.format_map(_SafeFormatDict(...))`` with the context dict from
# ``MockPlaybookGenerator._make_context``. Missing placeholders are left
# as literal ``{name}`` markers so they're easy to spot in tests.
_TEMPLATES: dict[str, dict[str, Any]] = {
    "cdp.credential_access.brute_force_admin_login": {
        "title": "Contain admin brute-force on {hostname}",
        "summary": (
            "Repeated failed admin authentications against {hostname} from "
            "{source_ip}. Lock the account, hunt for any successful auth, "
            "and block the source at the perimeter."
        ),
        "steps": [
            "Query the auth table for any **successful** login by `admin` from "
            "`{source_ip}` in the last 24h; if found, escalate to Sev-1.",
            "Lock the `admin` account on `{hostname}` and force a password "
            "rotation; revoke any active sessions and API tokens.",
            "Block `{source_ip}` at the network edge (WAF / firewall ACL) and "
            "tag it in the org's threat-intel feeds.",
            "Pull MFA/SSO logs for the same source IP across all assets to "
            "detect lateral attempts.",
            "Notify the asset owner ({asset_owner}) and on-call IR.",
            "Open an IR ticket linking alert id `{alert_id}` and rule "
            "`{rule_id}`; attach the matched-event JSON.",
            "After containment, review the brute-force rule's threshold and "
            "consider tightening `internal_ranges` or adding rate-limit alerting.",
        ],
    },
    "cdp.credential_access.iam_admin_policy_attached": {
        "title": "Investigate AWS AdministratorAccess attachment to {iam_user}",
        "summary": (
            "Direct attach of the AWS-managed `AdministratorAccess` policy to "
            "IAM user `{iam_user}` from `{source_ip}` — classic post-compromise "
            "privilege escalation. Verify intent, then revoke or quarantine."
        ),
        "steps": [
            "Verify with the asset owner ({asset_owner}) whether this "
            "AttachUserPolicy was authorized; if not, treat as Sev-1.",
            "Immediately call `iam:DetachUserPolicy` for `AdministratorAccess` "
            "on `{iam_user}` and rotate the user's access keys.",
            "Force a console password reset and revoke any active console "
            "sessions for `{iam_user}`.",
            "Pull CloudTrail for `{iam_user}` from `{source_ip}` over the last "
            "24h to scope blast radius (new keys, role assumes, S3/Secrets reads).",
            "Look for follow-on actions: `CreateAccessKey`, `CreateUser`, "
            "`AssumeRole`, S3 / RDS / Secrets Manager reads.",
            "Open a Sev-1 IR ticket with alert id `{alert_id}` and link the "
            "CloudTrail event.",
            "Add `{source_ip}` to the AWS WAF deny-list and review root-cause "
            "via the assumed-role chain.",
        ],
    },
    "cdp.execution.powershell_encoded_command": {
        "title": "Investigate encoded PowerShell on {hostname}",
        "summary": (
            "PowerShell launched with `-EncodedCommand` by user `{user}` on "
            "`{hostname}`, parented by `{parent_image}` — strong indicator of "
            "T1059.001 obfuscated payload execution."
        ),
        "steps": [
            "Decode the EncodedCommand payload offline (base64 → UTF-16LE) and "
            "capture indicators (URLs, IPs, scriptlets).",
            "Isolate `{hostname}` from the network if the payload references "
            "external infrastructure.",
            "Pull EDR/Sysmon process tree around `ProcessGuid` from the matched "
            "event for the full lineage.",
            "Search for the same payload hash or decoded URL across the fleet.",
            "Reset credentials for `{user}` and check for cached secrets or "
            "browser-stored tokens.",
            "Notify the asset owner ({asset_owner}) and open an IR ticket with "
            "alert id `{alert_id}`.",
            "Capture memory + disk artifacts for forensics if the scope expands.",
        ],
    },
    "cdp.execution.office_spawns_script_host": {
        "title": "Triage Office → script-host lineage on {hostname}",
        "summary": (
            "Office product `{parent_image}` on `{hostname}` spawned a script "
            "interpreter (`{image}`) for user `{user}` — textbook malicious-"
            "document execution chain (T1566.001 → T1059)."
        ),
        "steps": [
            "Locate the source document referenced in `{parent_command_line}` "
            "and submit it to the malware analysis sandbox.",
            "Isolate `{hostname}` until the document is cleared or remediated.",
            "Pull the full process tree around `ProcessGuid` from EDR.",
            "Search the fleet for the same document hash, sender, or URL.",
            "If outbound network connections fired, capture pcap for the host's egress.",
            "Reset `{user}` credentials and revoke active SSO/MFA sessions.",
            "Notify {asset_owner}; open an IR ticket with alert id `{alert_id}`.",
        ],
    },
    "cdp.persistence.new_service_install": {
        "title": "Investigate new Windows service on {hostname}",
        "summary": (
            "`sc.exe create` observed on `{hostname}` by `{user}` — installing "
            "a service is a common persistence primitive (T1543.003) and "
            "frequently runs as `LocalSystem`."
        ),
        "steps": [
            "Inspect the new service's `binPath` from the matched CommandLine; "
            "verify the binary's signature and hash.",
            "Pull the on-disk binary from `{hostname}` and submit to the malware "
            "analysis sandbox.",
            "If unsigned or unknown, stop and disable the service and isolate "
            "the host.",
            "Search the fleet for the same service name or binary hash.",
            "Review the parent process (`{parent_image}`) chain for the upstream "
            "initial-access vector.",
            "Reset `{user}` credentials if compromise is suspected.",
            "Notify {asset_owner} and open an IR ticket with alert id `{alert_id}`.",
        ],
    },
    "cdp.exfiltration.s3_large_object_egress": {
        "title": "Investigate large S3 egress by {iam_user}",
        "summary": (
            "GetObject of >50 MB from `{source_ip}` by `{iam_user}` — possible "
            "T1567.002 data exfiltration. Determine intent and scope quickly."
        ),
        "steps": [
            "Identify which S3 bucket(s) and key(s) were retrieved (see "
            "`requestParameters`); check classification labels.",
            "If the bucket holds regulated data, treat as a potential breach "
            "and engage privacy/legal.",
            "Pull all CloudTrail S3 events for `{iam_user}` and `{source_ip}` "
            "over the last 24h to compute total egress volume.",
            "Disable `{iam_user}`'s access keys and rotate; revoke any active "
            "console sessions.",
            "Block `{source_ip}` at the AWS WAF / VPC level.",
            "Notify {asset_owner}, IR, and (if regulated data) compliance/legal.",
            "Open a Sev-1 ticket with alert id `{alert_id}` and link the "
            "CloudTrail events.",
            "Add `{source_ip}` to the org's threat-intel deny list.",
        ],
    },
}

_GENERIC_TEMPLATE: dict[str, Any] = {
    "title": "Triage alert `{alert_id}`",
    "summary": "Generic triage playbook for `{rule_id}` (MITRE: {mitre}).",
    "steps": [
        "Confirm the alert is reproducible by re-running detection for `{rule_id}`.",
        "Pull surrounding telemetry (±15 minutes) on the same host/user/IP "
        "for context.",
        "Determine whether the matched activity has a known business owner "
        "({asset_owner}).",
        "Apply containment proportional to the severity (`{severity}`) and "
        "asset criticality (`{asset_criticality}`).",
        "Document the verdict and next steps; open a ticket with alert id "
        "`{alert_id}`.",
    ],
}


class MockPlaybookGenerator:
    """Deterministic templated playbook generator used for tests/CI/offline demo."""

    model = "cdp-mock-playbook-v1"

    def generate(self, enriched: EnrichedAlert) -> Playbook:
        alert = enriched.alert
        ctx = self._make_context(enriched)
        tpl = _TEMPLATES.get(alert.rule_id, _GENERIC_TEMPLATE)
        safe = _SafeFormatDict(ctx)
        return Playbook(
            alert_id=alert.id,
            title=tpl["title"].format_map(safe),
            summary=tpl["summary"].format_map(safe),
            steps=[s.format_map(safe) for s in tpl["steps"]],
            mitre_techniques=alert.mitre_techniques,
            model=self.model,
        )

    @staticmethod
    def _make_context(enriched: EnrichedAlert) -> dict[str, str]:
        alert = enriched.alert
        enrichment = enriched.enrichment
        event = alert.matched_event
        return {
            "alert_id": alert.id,
            "rule_id": alert.rule_id,
            "severity": alert.rule_level,
            "mitre": ", ".join(alert.mitre_techniques) or "(none)",
            "hostname": str(event.get("hostname") or "(unknown host)"),
            "user": str(
                event.get("User")
                or event.get("username")
                or event.get("userIdentity_userName")
                or "(unknown user)"
            ),
            "iam_user": str(event.get("userIdentity_userName") or "(unknown IAM user)"),
            "source_ip": str(
                event.get("source_ip")
                or event.get("sourceIPAddress")
                or "(unknown IP)"
            ),
            "image": str(event.get("Image") or "(unknown image)"),
            "parent_image": str(event.get("ParentImage") or "(unknown parent)"),
            "parent_command_line": str(event.get("ParentCommandLine") or ""),
            "asset_owner": enrichment.asset_owner or "(no listed owner)",
            "asset_criticality": enrichment.asset_criticality,
        }


# ---------- real Claude ----------


class ClaudePlaybookGenerator:
    """Calls Anthropic's Messages API with forced tool-use for the playbook schema."""

    def __init__(self, *, api_key: str, model: str, max_tokens: int = 1500) -> None:
        from anthropic import Anthropic

        self.model = model
        self._client = Anthropic(api_key=api_key)
        self._max_tokens = max_tokens

    def generate(self, enriched: EnrichedAlert) -> Playbook:
        user_text = render_alert_context(enriched)
        message = self._client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            system=PLAYBOOK_SYSTEM_PROMPT,
            tools=[cast(Any, PLAYBOOK_TOOL)],
            tool_choice={"type": "tool", "name": "submit_playbook"},
            messages=[
                {"role": "user", "content": [{"type": "text", "text": user_text}]}
            ],
        )
        for block in message.content:
            if (
                getattr(block, "type", None) == "tool_use"
                and getattr(block, "name", None) == "submit_playbook"
            ):
                tool_input = cast(dict[str, Any], block.input)  # type: ignore[union-attr]
                return Playbook(
                    alert_id=enriched.alert.id,
                    mitre_techniques=enriched.alert.mitre_techniques,
                    model=self.model,
                    **tool_input,
                )
        raise RuntimeError(
            "Claude did not emit a `submit_playbook` tool_use block "
            f"(stop_reason={message.stop_reason!r})."
        )


# ---------- factory ----------


def make_playbook_generator(settings: Settings | None = None) -> PlaybookGenerator:
    """Return :class:`ClaudePlaybookGenerator` if a key is set, else :class:`MockPlaybookGenerator`."""
    cfg = settings or Settings.load()
    if cfg.has_anthropic_key:
        assert cfg.anthropic_api_key is not None
        return ClaudePlaybookGenerator(api_key=cfg.anthropic_api_key, model=cfg.model)
    return MockPlaybookGenerator()
