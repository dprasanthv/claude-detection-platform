# claude-detection-platform

**Sigma-based detection-as-code platform with Claude-powered alert triage and incident-response playbooks, measured by a hand-labeled eval harness.**

## What it does

End-to-end detection and response engineering in one repo:

1. **Ingest** — generate deterministic synthetic telemetry across three sources (Windows process creation, authentication, AWS CloudTrail), with planted ATT&CK attacks plus deliberately-benign-but-rule-firing events to give the eval harness a real TP-vs-FP signal.
2. **Detect** — compile Sigma YAML rules into parameterized DuckDB SQL. Ships with 6 rules across 4 ATT&CK tactics (credential access, execution, persistence, exfiltration) that emit **89 alerts** against the synthetic dataset.
3. **Enrich** — attach static context to each alert (public/private IP class, asset criticality and owner from `enrichment/assets.yaml`, threat-intel hits).
4. **Triage** — classify each alert as `true_positive | false_positive | needs_investigation` via Claude (forced tool-use for structured output) or a deterministic offline mock baseline.
5. **Playbook** — generate a 5–8 step containment plan referencing specific matched-event fields, the asset's owner, and the rule's MITRE techniques.
6. **Eval** — score triager predictions against 20 hand-labeled alerts. Reports precision / recall / F1 for both TP- and FP-as-positive framings, under two collapse modes for `needs_investigation`.
7. **Surface** — expose every phase over a Typer CLI and a FastAPI service. `cdp demo` runs the whole pipeline end-to-end in one command.

The whole thing is hermetic: deterministic seeds, offline mock fallback for the Claude path, and no external services. A reviewer can see real output in under a minute with zero credentials.

> 📐 **Design deep-dive** — [`ARCHITECTURE.md`](ARCHITECTURE.md): system diagram, module map, and the "why DuckDB / why Sigma / why forced tool-use" answers.
> 📊 **Eval methodology** — [`evals/README.md`](evals/README.md): collapse modes, metric definitions, reproduction recipe.
> 🛡️ **Rule catalogue** — [`detections/README.md`](detections/README.md): MITRE coverage table and Sigma subset reference.

## How to run

**Prerequisites**: Docker (Docker Desktop on macOS, docker-ce on Linux).

```bash
# Build the image — one-time, layer-cached afterwards.
docker compose build

# The elevator pitch: one command, end-to-end.
# Runs ingest → detect → enrich → triage → playbook against each other with
# rich-rendered banners. Uses the deterministic offline mock, so no key needed.
docker compose run --rm cdp cdp demo --limit 3
```

### Phase-by-phase

```bash
# 1. Generate synthetic telemetry (~538 events across 3 Parquet tables → ./data)
docker compose run --rm cdp cdp ingest --synthetic

# 2. Run Sigma rules (89 alerts across 6 rules / 4 tactics)
docker compose run --rm cdp cdp detect --limit 10           # pretty table
docker compose run --rm cdp cdp detect --format json        # JSON for piping

# 3. Triage a single alert (mock triager, no key required)
docker compose run --rm cdp cdp triage \
  --alert-id cdp.exfiltration.s3_large_object_egress-8f29f8ebcc34 --mock

# 4. Generate a containment + investigation playbook
docker compose run --rm cdp cdp playbook \
  --alert-id cdp.persistence.new_service_install-87302844ce97 --mock

# 5. Run the eval harness → writes reports under ./evals/reports/
docker compose run --rm cdp cdp eval --mock --out-name latest

# 6. Serve the FastAPI surface (healthz, rules, alerts, triage, playbook)
docker compose run --rm --service-ports cdp cdp serve --host 0.0.0.0
# -> http://localhost:8000/docs for the interactive OpenAPI UI
```

### With real Claude

Set `ANTHROPIC_API_KEY` in your shell or a project-root `.env` file, then pass `--claude` to any of `demo`, `triage`, `playbook`, or `eval`:

```bash
ANTHROPIC_API_KEY=sk-ant-... docker compose run --rm -e ANTHROPIC_API_KEY \
  cdp cdp demo --claude
```

### Editing on the host

`./cdp/`, `./detections/`, `./enrichment/`, `./evals/`, `./tests/`, and `./data/` are all bind-mounted into the container. Edit Sigma rules, the asset DB, eval ground truth, or Python source on the host and the next `cdp` invocation picks it up — no rebuild needed.

## Running the tests

Hermetic: no network, no API key, no writes to the real `./data/`. Full suite runs in ~10 s.

```bash
# Full test suite (~200 tests: models, store, ingest, sigma, engine, prompts,
# enrich, triage, playbook, cli, api, eval)
docker compose run --rm cdp pytest -q

# With coverage
docker compose run --rm cdp pytest --cov=cdp --cov-report=term-missing

# Lint + type-check
docker compose run --rm cdp ruff check cdp tests evals
docker compose run --rm cdp mypy cdp evals

# Validate every Sigma rule without running detections (exits 0/1 for CI use).
# --strict promotes unmapped-logsource warnings to failures.
docker compose run --rm cdp cdp validate
docker compose run --rm cdp cdp validate --strict
```

## Project layout

```
cdp/                  # installable Python package — the platform itself
detections/           # Sigma rule catalogue (live-editable, bind-mounted)
enrichment/           # assets.yaml — asset DB for cdp/enrich.py
evals/                # ground truth + eval harness + seed report
tests/                # pytest suite (hermetic, ~200 tests)
data/                 # generated Parquet files (gitignored)
ARCHITECTURE.md       # design decisions + system diagram
```

## License

MIT. See [`LICENSE`](LICENSE).
