"""Static enrichment layer for alerts.

Pulls a few cheap, pre-computed signals (IP private/public, country,
asset criticality / owner / env) from a YAML asset DB. The DB is
intentionally small and human-readable — this is a SOC stand-in, not an
ITAM system. Adding a new host means editing one YAML file.

The triage and playbook layers consume :class:`Enrichment` rather than
reaching into the asset DB themselves, so swapping the DB out for a real
backend (CMDB, Snowflake table, etc.) is a single-file change.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import yaml

from cdp.models import Alert, AssetCriticality, EnrichedAlert, Enrichment

DEFAULT_ASSET_DB = Path(__file__).resolve().parent.parent / "enrichment" / "assets.yaml"

# Fields on a matched event that may carry an IP, in priority order.
IP_FIELDS = ("source_ip", "sourceIPAddress", "src_ip", "client_ip")
# Fields on a matched event that identify a host or IAM principal.
ASSET_KEY_FIELDS = ("hostname", "host", "Computer", "userIdentity_userName")
# Allowed criticality values per cdp.models.Enrichment.
_ALLOWED_CRITICALITIES = frozenset({"low", "medium", "high", "critical", "unknown"})


def load_asset_db(path: Path = DEFAULT_ASSET_DB) -> dict[str, Any]:
    """Load the asset DB YAML. Returns an empty dict if the file is missing.

    No caching: the file is small and only consulted once per alert; caching
    would create cross-test bleed and complicate hot-reload during rule
    authoring. If profiling shows this on the hot path later, add a
    process-lifetime cache here.
    """
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"asset DB at {path} must be a mapping at top level")
    return raw


def enrich_alert(alert: Alert, asset_db: Mapping[str, Any] | None = None) -> Enrichment:
    """Build the :class:`Enrichment` for one alert from the asset DB."""
    db = asset_db if asset_db is not None else load_asset_db()
    event = alert.matched_event

    extras: dict[str, Any] = {}

    ip = _find_ip(event)
    is_private: bool | None = None
    country: str | None = None
    if ip is not None:
        is_private, ip_extras = _classify_ip(ip)
        extras.update(ip_extras)
        if is_private is False:
            ti = (db.get("known_bad_ips") or {}).get(ip)
            if isinstance(ti, dict):
                country = ti.get("country")
                if "notes" in ti:
                    extras["threat_intel"] = ti["notes"]

    criticality: AssetCriticality = "unknown"
    owner: str | None = None
    env: str | None = None
    asset_key = _find_asset_key(event)
    if asset_key is not None:
        record = (db.get("hosts") or {}).get(asset_key)
        if not isinstance(record, dict):
            record = (db.get("iam_users") or {}).get(asset_key)
        if isinstance(record, dict):
            raw_crit = str(record.get("criticality", "unknown"))
            if raw_crit in _ALLOWED_CRITICALITIES:
                criticality = cast(AssetCriticality, raw_crit)
            owner = record.get("owner")
            env = record.get("env")
            if "notes" in record:
                extras["asset_notes"] = record["notes"]

    return Enrichment(
        alert_id=alert.id,
        ip_is_private=is_private,
        ip_country=country,
        asset_criticality=criticality,
        asset_owner=owner,
        asset_env=env,
        extras=extras,
    )


def enriched_for(
    alert: Alert,
    *,
    context_events: list[dict[str, Any]] | None = None,
    asset_db: Mapping[str, Any] | None = None,
) -> EnrichedAlert:
    """Bundle ``alert + enrichment + context_events`` into one :class:`EnrichedAlert`."""
    return EnrichedAlert(
        alert=alert,
        enrichment=enrich_alert(alert, asset_db),
        context_events=context_events or [],
    )


# ---------- internals ----------


def _find_ip(event: Mapping[str, Any]) -> str | None:
    for f in IP_FIELDS:
        v = event.get(f)
        if isinstance(v, str) and v:
            return v
    return None


def _find_asset_key(event: Mapping[str, Any]) -> str | None:
    for f in ASSET_KEY_FIELDS:
        v = event.get(f)
        if isinstance(v, str) and v:
            return v
    return None


def _classify_ip(ip_str: str) -> tuple[bool | None, dict[str, Any]]:
    """Return ``(is_private, extras)``. ``is_private`` is None if unparseable."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, {"ip": ip_str, "ip_class": "invalid"}
    extras: dict[str, Any] = {"ip": ip_str}
    if ip.is_loopback:
        extras["ip_class"] = "loopback"
    elif ip.is_link_local:
        extras["ip_class"] = "link_local"
    elif ip.is_private:
        extras["ip_class"] = "private"
    else:
        extras["ip_class"] = "public"
    return ip.is_private, extras
