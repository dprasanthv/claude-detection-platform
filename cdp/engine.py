"""Detection engine: load Sigma rules, run them against the store, emit Alerts."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cdp.models import Alert, SigmaRule
from cdp.sigma import compile_rule, load_rules, resolve_table
from cdp.store import Store

DEFAULT_RULES_DIR = Path("detections")


class DetectionEngine:
    """Run a directory of Sigma rules against the telemetry store."""

    def __init__(self, store: Store, rules_dir: Path | str | None = None) -> None:
        self.store = store
        self.rules_dir = Path(rules_dir or DEFAULT_RULES_DIR).expanduser().resolve()
        self._rules: list[SigmaRule] = []

    @property
    def rules(self) -> list[SigmaRule]:
        return list(self._rules)

    def load_rules(self) -> list[SigmaRule]:
        if not self.rules_dir.exists():
            raise FileNotFoundError(f"rules dir not found: {self.rules_dir}")
        self._rules = load_rules(self.rules_dir)
        return self._rules

    def run_all(self) -> list[Alert]:
        """Execute every loaded rule and return the flat list of alerts."""
        if not self._rules:
            self.load_rules()
        if not self.store.tables():
            self.store.load_all()

        loaded_tables = set(self.store.tables())
        alerts: list[Alert] = []
        for rule in self._rules:
            table = resolve_table(rule.logsource)
            if not table or table not in loaded_tables:
                # Either the logsource doesn't map to one of our tables, or the
                # parquet file simply isn't present yet. Skip silently — this
                # is a reasonable detection-engineering default.
                continue
            compiled = compile_rule(rule, table=table)
            rows = self.store.query(compiled.to_sql(), compiled.params)
            for row in rows:
                alerts.append(_make_alert(rule, table, row))
        return alerts


# ---------- Alert construction helpers ----------

def _matched_at(row: dict[str, Any]) -> datetime:
    """Best-effort extraction of an event timestamp; falls back to now()."""
    ts = row.get("timestamp")
    if isinstance(ts, datetime):
        return ts.astimezone(UTC) if ts.tzinfo else ts.replace(tzinfo=UTC)
    if isinstance(ts, str):
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _alert_id(rule: SigmaRule, row: dict[str, Any]) -> str:
    """Deterministic alert id: ``{rule_id}-{12-char sha256 of event payload}``."""
    payload = json.dumps(row, sort_keys=True, default=str).encode()
    digest = hashlib.sha256(payload).hexdigest()[:12]
    return f"{rule.id}-{digest}"


def _make_alert(rule: SigmaRule, table: str, row: dict[str, Any]) -> Alert:
    return Alert(
        id=_alert_id(rule, row),
        rule_id=rule.id,
        rule_title=rule.title,
        rule_level=rule.level,
        rule_tags=list(rule.tags),
        mitre_techniques=rule.mitre_techniques,
        logsource_table=table,
        matched_event=row,
        matched_at=_matched_at(row),
        rule_sha256=rule.sha256,
    )
