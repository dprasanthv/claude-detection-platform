# claude-detection-platform

Sigma-based detection-as-code platform with Claude-powered alert triage and response playbooks. Built to demonstrate end-to-end detection & response engineering: telemetry ingestion, detection rules, AI-augmented analysis, and measurable evals.

The current build provides reproducible synthetic telemetry generation across three event sources (Windows process creation, authentication, AWS CloudTrail) with deterministic attacks planted in benign noise, JSONL→Parquet conversion via DuckDB, and a SQL query layer over the resulting Parquet files.

## Run

**Prerequisites**: Docker (Docker Desktop on macOS, docker-ce on Linux).

```bash
# Build the image (one time; layer-cached afterward)
docker compose build

# Verify the install
docker compose run --rm cdp cdp version
# 0.1.0

# Generate the synthetic dataset (~529 events across 3 Parquet tables under ./data)
docker compose run --rm cdp cdp ingest --synthetic

# Query the dataset — count admin login failures grouped by source IP
# (the 50-event burst from 185.220.101.45 is the planted T1110 brute force)
docker compose run --rm cdp python -c "from cdp.store import Store; s = Store(); s.load_all(); print(s.query(\"select source_ip, count(*) as failures from authentication where username='admin' and result='failure' group by source_ip order by failures desc\"))"
```

Generated Parquet files land in `./data/` on the host thanks to the bind mount in `docker-compose.yml`.
