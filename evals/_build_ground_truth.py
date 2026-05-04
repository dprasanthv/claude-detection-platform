"""One-shot generator for ``evals/ground_truth.yaml``.

Re-run after any change to ``cdp/ingest.py`` that affects alert IDs:

    docker compose run --rm cdp python evals/_build_ground_truth.py

The labels themselves come from *knowledge of the synthetic dataset*, not
from any trained model — these are the answers a competent human analyst
would give if walked through each event:

* Tor exit node (185.220.101.45) traffic → ``true_positive``
* Coffee-shop external IP (198.51.100.10) brute-force → ``false_positive``
  (small burst, no TI hit, immediately followed by successful login)
* Internal-IP analytics-bucket S3 egress (10.0.5.12 / dev-alice / acme-
  analytics-exports) → ``false_positive``
* All other planted attacks → ``true_positive``

The output is checked into the repo. Re-running is only required if rule IDs
or event content shifts.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from cdp.engine import DEFAULT_RULES_DIR, DetectionEngine
from cdp.ingest import generate_synthetic_dataset
from cdp.store import Store

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
OUT = REPO_ROOT / "evals" / "ground_truth.yaml"


def _label(alert: Any) -> tuple[str, str] | None:
    """Return ``(verdict, rationale)`` for an alert, or ``None`` to skip.

    Rationale strings are short hand-written explanations the eval report
    surfaces alongside the prediction, so a reader can see *why* an alert
    is labeled the way it is.
    """
    rid = alert.rule_id
    ev = alert.matched_event

    if rid == "cdp.credential_access.brute_force_admin_login":
        ip = ev.get("source_ip")
        if ip == "185.220.101.45":
            return ("true_positive",
                    "Sustained 50-event admin brute-force burst from a known "
                    "Tor exit node — textbook T1110.")
        if ip == "198.51.100.10":
            return ("false_positive",
                    "Small 6-event admin failure burst from a public-but-"
                    "unflagged IP, immediately followed by a successful "
                    "auth — classic 'forgot the password, got it on the 7th "
                    "try' scenario.")
        return None
    if rid == "cdp.credential_access.iam_admin_policy_attached":
        return ("true_positive",
                "Direct AttachUserPolicy of AWS-managed AdministratorAccess "
                "by `dev-bob` from a Tor exit node — privilege escalation "
                "after credential theft (T1078).")
    if rid == "cdp.execution.powershell_encoded_command":
        return ("true_positive",
                "PowerShell launched with -EncodedCommand by `alice`, parented "
                "by WINWORD.EXE — Empire-style obfuscated payload (T1059.001).")
    if rid == "cdp.execution.office_spawns_script_host":
        return ("true_positive",
                "Office product spawned a script interpreter — textbook "
                "malicious-document execution chain (T1566.001 → T1059).")
    if rid == "cdp.persistence.new_service_install":
        return ("true_positive",
                "`sc.exe create` of an unsigned binary in ProgramData — "
                "service-based persistence primitive (T1543.003).")
    if rid == "cdp.exfiltration.s3_large_object_egress":
        ip = ev.get("sourceIPAddress")
        if ip == "185.220.101.45":
            return ("true_positive",
                    "200MB+ GetObject of `acme-customer-pii` by `dev-bob` "
                    "from a Tor exit node — T1567.002 candidate.")
        if ip == "10.0.5.12":
            return ("false_positive",
                    "80MB GetObject of `acme-analytics-exports` by `dev-alice` "
                    "from an internal AWS-VPC IP — sanctioned nightly "
                    "analytics export, known-good user/bucket combination.")
        return None
    return None


def main() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    generate_synthetic_dataset(DATA_DIR)

    with Store() as store:
        store.load_all()
        engine = DetectionEngine(store, rules_dir=DEFAULT_RULES_DIR)
        engine.load_rules()
        alerts = engine.run_all()

    # Bucket alerts by (rule_id, verdict) so we sample evenly.
    buckets: dict[tuple[str, str], list[tuple[Any, str, str]]] = defaultdict(list)
    for alert in alerts:
        labelled = _label(alert)
        if labelled is None:
            continue
        verdict, rationale = labelled
        buckets[(alert.rule_id, verdict)].append((alert, verdict, rationale))

    # Sampling plan: 20 alerts total.
    # 4 brute_force TP + 3 brute_force FP
    # 1 iam admin TP
    # 1 powershell encoded TP
    # 2 office spawn TP
    # 1 new service TP
    # 5 s3 egress TP + 3 s3 egress FP
    plan: list[tuple[str, str, int]] = [
        ("cdp.credential_access.brute_force_admin_login", "true_positive", 4),
        ("cdp.credential_access.brute_force_admin_login", "false_positive", 3),
        ("cdp.credential_access.iam_admin_policy_attached", "true_positive", 1),
        ("cdp.execution.powershell_encoded_command", "true_positive", 1),
        ("cdp.execution.office_spawns_script_host", "true_positive", 2),
        ("cdp.persistence.new_service_install", "true_positive", 1),
        ("cdp.exfiltration.s3_large_object_egress", "true_positive", 5),
        ("cdp.exfiltration.s3_large_object_egress", "false_positive", 3),
    ]

    rows: list[dict[str, Any]] = []
    for rid, verdict, n in plan:
        bucket = sorted(buckets[(rid, verdict)], key=lambda x: x[0].matched_at)
        if len(bucket) < n:
            raise RuntimeError(
                f"asked for {n} alerts of {(rid, verdict)} but only "
                f"{len(bucket)} are available in the synthetic dataset"
            )
        # Take an evenly-spaced sample so we cover the time range, not just
        # the start of a burst (especially relevant for the 50-event Tor
        # brute-force where the first few are temporally clustered).
        step = max(len(bucket) // n, 1)
        chosen = [bucket[i * step] for i in range(n)]
        for alert, v, rationale in chosen:
            rows.append({
                "alert_id": alert.id,
                "rule_id": alert.rule_id,
                "verdict": v,
                "rationale": rationale,
                "matched_at": alert.matched_at.isoformat(),
            })

    out: dict[str, Any] = {
        "version": 1,
        "description": (
            "Hand-labeled ground-truth for the Phase 5 eval harness. "
            "Each row pins an alert id from the deterministic synthetic "
            "dataset (see cdp/ingest.py) to a verdict a competent analyst "
            "would assign after reading the matched event + enrichment."
        ),
        "alerts": rows,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(yaml.safe_dump(out, sort_keys=False, width=100))
    print(f"wrote {OUT} ({len(rows)} alerts)")
    print(f"  TP: {sum(1 for r in rows if r['verdict']=='true_positive')}")
    print(f"  FP: {sum(1 for r in rows if r['verdict']=='false_positive')}")


if __name__ == "__main__":
    main()
