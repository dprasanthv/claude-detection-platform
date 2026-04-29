# claude-detection-platform

Sigma-based detection-as-code platform with Claude-powered alert triage and response playbooks. Built to demonstrate end-to-end detection & response engineering: telemetry ingestion, detection rules, AI-augmented analysis, and measurable evals.

The current build provides reproducible synthetic telemetry generation across three event sources (Windows process creation, authentication, AWS CloudTrail) with deterministic attacks planted in benign noise, JSONL→Parquet conversion via DuckDB, a SQL query layer over the resulting Parquet files, a Sigma-based detection engine that compiles 6 rules across 4 ATT&CK tactics (credential_access, execution, persistence, exfiltration) into parameterized DuckDB queries, and a Claude-powered triage + playbook layer that classifies each alert as `true_positive | false_positive | needs_investigation` and generates a tailored 5–8 step containment + investigation plan. A deterministic offline mock keeps the entire pipeline runnable without an Anthropic API key.

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

# Run all Sigma rules under ./detections — emits 80 alerts across 6 rules / 4 tactics
docker compose run --rm cdp cdp detect --limit 10

# Same thing as JSON for downstream piping (one alert per matched event)
docker compose run --rm cdp cdp detect --format json | head -50
```

Generated Parquet files land in `./data/` on the host thanks to the bind mount in `docker-compose.yml`. Sigma rules under `./detections/` are also bind-mounted into the container, so editing or adding a rule on the host takes effect on the next `cdp detect` run without rebuilding the image. The rule authoring guide (modifiers, condition grammar, MITRE coverage table) lives in [`detections/README.md`](detections/README.md).

## Triage and playbooks

The Claude AI layer adds three subcommands. All accept input via `--alert-json FILE`, stdin, or `--alert-id <id>` (re-runs detection to look up a single alert). All have a `--mock` flag that forces the deterministic offline path even when `ANTHROPIC_API_KEY` is set.

```bash
# Attach static enrichment (IP class, asset criticality, threat-intel hits)
docker compose run --rm cdp bash -c "cdp detect --format json | head -c 4000 | cdp enrich"

# Triage one alert via the offline mock — true_positive / false_positive / needs_investigation
docker compose run --rm cdp cdp triage --alert-id cdp.exfiltration.s3_large_object_egress-f1c6f3c29ee0 --mock

# Pipe pattern: detect → filter to one rule → triage with mock
docker compose run --rm cdp bash -c \
  "cdp detect --format json | python -c 'import json,sys; \
   print(json.dumps([a for a in json.load(sys.stdin) \
   if a[\"rule_id\"]==\"cdp.persistence.new_service_install\"]))' \
   | cdp triage --mock"

# Generate a containment + investigation playbook (5-8 steps, MITRE-tagged)
docker compose run --rm cdp cdp playbook --alert-id cdp.persistence.new_service_install-87302844ce97 --mock

# Real Claude (set the key in your shell or in a project-root .env file)
ANTHROPIC_API_KEY=sk-ant-... docker compose run --rm -e ANTHROPIC_API_KEY cdp \
  cdp triage --alert-id cdp.execution.powershell_encoded_command-...
```

Triage output is a `TriageResult` per alert with `verdict`, `confidence` ∈ [0, 1], `reasoning`, and 3-5 `next_steps`. Playbook output is a `Playbook` per alert with `title`, `summary`, and 5-8 numbered `steps` referencing specific event fields, the asset's owner from `enrichment/assets.yaml`, and the rule's MITRE techniques. Both are emitted as JSON (one record per alert) for downstream piping. The asset DB is bind-mounted into the container — edit `enrichment/assets.yaml` on the host and the next run picks it up.

## Tests

The test suite is hermetic: no network calls, no Anthropic API key required, no writes to the repo's `./data/` directory. The synthetic dataset is generated once per pytest session and copied into per-test tmp dirs.

```bash
# Full test suite (~157 tests covering models, store, ingest, sigma, engine, prompts, enrich, triage, playbook, cli)
docker compose run --rm cdp pytest -q

# With coverage report (terminal, missing-line annotations)
docker compose run --rm cdp pytest --cov=cdp --cov-report=term-missing

# Run a single module or test
docker compose run --rm cdp pytest tests/test_engine.py -v
docker compose run --rm cdp pytest tests/test_sigma.py::test_compile_list_value_or_expanded

# Lint + type-check (matches the standards enforced in pyproject.toml)
docker compose run --rm cdp ruff check cdp tests
docker compose run --rm cdp mypy cdp

# Validate every Sigma rule under detections/ without running detections.
# Exits 0 on success, 1 on any compile failure. Add --strict to also fail on
# rules whose logsource doesn't map to a known table.
docker compose run --rm cdp cdp validate
docker compose run --rm cdp cdp validate --strict
```

`tests/` is bind-mounted into the container alongside `cdp/` and `detections/`, so editing a test on the host takes effect on the next `pytest` invocation without rebuilding the image.