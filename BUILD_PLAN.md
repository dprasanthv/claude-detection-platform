# Build Plan — `claude-detection-platform`

Living document that tracks the phased implementation of this project. **Each phase has an explicit checkpoint**: build stops at the end of a phase, we review together, then the next phase begins.

> Source of truth for state. Update the **Status** column and **Current state** section at every checkpoint.

## Status legend

- ⬜ **Not started**
- 🟡 **In progress**
- ✅ **Done (checkpoint passed)**
- 🔁 **Revisiting / rework**

## Phase overview

| # | Phase | What it delivers | Status |
|---|---|---|---|
| 0 | Scaffolding | Repo metadata, package skeleton, env template | ✅ |
| 1 | Data foundation | Telemetry models, synthetic + Mordor ingest, DuckDB store | ✅ |
| 2 | Detection engine | Sigma parser → DuckDB SQL, 6+ rules across 4 ATT&CK tactics | ⬜ |
| 3 | Claude AI layer | Triage + enrichment + playbook generation, mock fallback | ⬜ |
| 4 | API + CLI | FastAPI service, Typer CLI for end-to-end demo | ⬜ |
| 5 | Eval harness | Ground-truth YAML, triage eval, markdown report | ⬜ |
| 6 | Tests + CI | pytest suite, GitHub Actions (lint, test, sigma validate, nightly eval) | ⬜ |
| 7 | IaC + docs | Terraform Lambda/API-GW module, README, ARCHITECTURE.md (Mermaid) | ⬜ |

## Checkpoint protocol

At each phase boundary:

1. I update **Status** and **Current state** in this file.
2. I post a short summary: what was built, what works, what's next.
3. **You review**, run it if you want, and either approve or request changes.
4. Only after your ✅ do we move to the next phase.

---

## Phase 0 — Scaffolding

**Goal**: the repo is a valid installable Python project with clean metadata and sensible folder layout. No logic yet.

**Deliverables**
- `pyproject.toml` — deps (`duckdb`, `pyyaml`, `pydantic`, `fastapi`, `anthropic`, `typer`, plus dev: `pytest`, `ruff`, `mypy`), metadata, entry point `cdp` → `cdp.cli:app`.
- `.gitignore` — Python, venv, data/, eval reports, Terraform, `.env`.
- `LICENSE` — MIT.
- `.env.example` — `ANTHROPIC_API_KEY`, `CDP_MODEL`, `CDP_DATA_DIR`.
- `data/.gitkeep`, `evals/reports/.gitkeep` — preserve empty dirs.
- `cdp/__init__.py` — package marker, version, public re-exports.

**Design notes**
- Package is named **`cdp`** (not `platform/`) — avoids shadowing Python's stdlib `platform` module. Documented in `ARCHITECTURE.md` later.

**Acceptance criteria**
- `pip install -e .[dev]` succeeds in a fresh venv.
- `python -c "import cdp; print(cdp.__version__)"` prints `0.1.0`.

**Files touched**: `pyproject.toml`, `.gitignore`, `LICENSE`, `.env.example`, `data/.gitkeep`, `evals/reports/.gitkeep`, `cdp/__init__.py`.

---

## Phase 1 — Data foundation

**Goal**: reproducibly produce a realistic telemetry dataset on disk and query it with SQL.

**Deliverables**
- `cdp/models.py` — Pydantic models: `Event`, `Alert`, `SigmaRule`, `TriageResult`, `Playbook`.
- `cdp/config.py` — settings loader (`CDP_DATA_DIR`, model name, API key).
- `cdp/ingest.py`
  - `generate_synthetic_dataset()` — deterministic fake Windows process, auth, and AWS CloudTrail events seeded with known attacks (brute force, encoded PowerShell, new service, unusual S3 egress) buried in benign noise.
  - `load_mordor(scenario)` — optional download of a Mordor scenario URL → Parquet (no-op if offline).
  - Writes three Parquet files: `windows_process_creation.parquet`, `authentication.parquet`, `aws_cloudtrail.parquet`.
- `cdp/store.py` — `Store` class wrapping DuckDB. `load_parquet(path, table)`, `query(sql) -> list[dict]`, `tables() -> list[str]`.
- Minimal CLI stub `cdp/cli.py` with `cdp ingest` command.

**Acceptance criteria**
- `cdp ingest --synthetic` produces three Parquet files under `data/`.
- `Store().query("select count(*) from windows_process_creation")` returns > 100 rows.
- Each synthetic attack has at least one matching event buried among ≥ 10× benign events.

**Files touched**: `cdp/models.py`, `cdp/config.py`, `cdp/ingest.py`, `cdp/store.py`, `cdp/cli.py`.

---

## Phase 2 — Detection engine

**Goal**: convert Sigma YAML rules into DuckDB SQL, run them against the store, emit structured alerts.

**Deliverables**
- `cdp/sigma.py`
  - Parse Sigma YAML → `SigmaRule` (title, id, logsource, detection, condition, level, tags).
  - Support field modifiers: `contains`, `startswith`, `endswith`, `re`, `gt`, `gte`, `lt`, `lte`, default equals.
  - Support list values (OR-expanded).
  - Condition grammar: names, `and`, `or`, `not`, parentheses, `1 of selection_*`, `all of selection_*`.
  - Compile to DuckDB SQL (`WHERE ...` against the resolved table).
- `cdp/engine.py`
  - `DetectionEngine(store, rules_dir)` → `run_all() -> list[Alert]`.
  - Maps `logsource.product`/`category`/`service` → table name.
  - Emits `Alert` with rule id, title, level, mitre tags, matched event payload, rule SHA.
- `detections/` — 6 Sigma rules:
  - `credential_access/brute_force_login.yml` (T1110)
  - `credential_access/suspicious_iam_policy_change.yml` (T1078)
  - `execution/powershell_encoded_command.yml` (T1059.001)
  - `execution/unusual_process_lineage.yml` (T1059)
  - `persistence/new_service_install.yml` (T1543.003)
  - `exfiltration/unusual_s3_data_egress.yml` (T1567.002)
- `detections/README.md` — rule authoring guide + MITRE mapping table.
- CLI: `cdp detect` — loads rules, queries store, prints alerts as JSON.

**Acceptance criteria**
- `cdp detect` emits ≥ 4 distinct alerts against the synthetic dataset.
- All 6 rules validate (parse cleanly) under `cdp.sigma.parse_rule_file`.
- At least one rule per ATT&CK tactic listed above fires.

**Files touched**: `cdp/sigma.py`, `cdp/engine.py`, `cdp/cli.py`, `detections/*.yml`, `detections/README.md`.

---

## Phase 3 — Claude AI layer

**Goal**: add Claude-driven triage, enrichment, and playbook generation. Must work offline with a deterministic mock when `ANTHROPIC_API_KEY` is absent (so CI and tests are hermetic).

**Deliverables**
- `cdp/triage.py`
  - `triage_alert(alert, context_events) -> TriageResult` — classify `true_positive | false_positive | needs_investigation`, give reasoning, suggest 3 investigative steps.
  - Uses Anthropic SDK with tool-use / structured output.
  - `MockTriager` fallback for offline runs (deterministic heuristic based on rule level + keywords).
- `cdp/enrich.py`
  - `enrich_alert(alert) -> EnrichedAlert` — mock IP geolocation (`is_private`, `country`), asset criticality lookup from `enrichment/assets.yaml`.
- `cdp/playbook.py`
  - `generate_playbook(alert, enrichment) -> Playbook` — Claude produces a 5–8 step response plan tailored to rule + enrichment; mock fallback returns a canned-but-relevant plan.
- `enrichment/assets.yaml` — small asset DB (`host → criticality, owner, env`).
- CLI: `cdp triage <alert-json>`, `cdp playbook <alert-json>`.

**Acceptance criteria**
- With `ANTHROPIC_API_KEY` unset, `cdp triage` returns a valid `TriageResult` via the mock.
- With key set, a real Claude call produces a structured JSON response validated by Pydantic.
- Playbook output has numbered steps and references the alert's MITRE tag.

**Files touched**: `cdp/triage.py`, `cdp/enrich.py`, `cdp/playbook.py`, `cdp/cli.py`, `enrichment/assets.yaml`.

---

## Phase 4 — API + end-to-end CLI

**Goal**: expose the platform as a REST service; single `cdp demo` command runs ingest → detect → enrich → triage → playbook.

**Deliverables**
- `cdp/api.py`
  - `GET /healthz`
  - `GET /alerts` (from last detection run, optionally filtered by level / mitre tag)
  - `POST /alerts/{id}/triage`
  - `POST /alerts/{id}/playbook`
  - `GET /rules`
- `cdp/cli.py` gains `cdp serve` (uvicorn) and `cdp demo` (runs full pipeline, prints a rich summary).

**Acceptance criteria**
- `cdp serve` starts; `curl localhost:8000/alerts` returns JSON list.
- `cdp demo` end-to-end succeeds against the synthetic dataset with mock triage.

**Files touched**: `cdp/api.py`, `cdp/cli.py`.

---

## Phase 5 — Eval harness

**Goal**: *measurable* Claude triage performance. This is the differentiator — hiring managers see "I evaluated my LLM use".

**Deliverables**
- `evals/ground_truth.yaml` — 20 hand-labeled alerts from the synthetic dataset (mix of TPs and FPs, with rationale).
- `evals/run_eval.py`
  - Runs both `MockTriager` and (if key present) real Claude.
  - Computes precision, recall, F1, agreement rate vs. ground truth.
  - Emits `evals/reports/latest.md` + `evals/reports/latest.json`.
- `evals/README.md` — methodology, caveats, how to reproduce.
- Pre-generated `evals/reports/seed-run.md` so the repo has results without requiring an API key.

**Acceptance criteria**
- `python evals/run_eval.py --mock` produces a markdown report with populated metrics.
- Report includes a confusion matrix and per-alert disagreement list.

**Files touched**: `evals/ground_truth.yaml`, `evals/run_eval.py`, `evals/README.md`, `evals/reports/seed-run.md`.

---

## Phase 6 — Tests + CI

**Goal**: green CI badge, confidence the project stays healthy.

**Deliverables**
- `tests/test_sigma.py` — parse each rule, spot-check SQL compilation.
- `tests/test_engine.py` — deterministic dataset → known alerts.
- `tests/test_store.py` — ingest + query roundtrip.
- `tests/test_triage_mock.py` — mock triager contract + schema.
- `tests/test_api.py` — FastAPI `TestClient` over the main endpoints.
- `tests/conftest.py` — shared fixtures (ephemeral data dir, seeded store).
- `.github/workflows/ci.yml` — ruff, mypy, pytest, sigma rule validation.
- `.github/workflows/detection-eval.yml` — nightly: run detections, commit `evals/reports/YYYY-MM-DD.md`.

**Acceptance criteria**
- `pytest` passes locally.
- CI config is lint-clean (we can't run GitHub Actions without pushing, but syntax must be valid).

**Files touched**: `tests/*.py`, `.github/workflows/*.yml`.

---

## Phase 7 — IaC + docs + polish

**Goal**: the README is the hiring-manager landing page. IaC shows infra fluency.

**Deliverables**
- `infra/terraform/`
  - `main.tf` — Lambda + API Gateway + IAM role wiring.
  - `variables.tf`, `outputs.tf`, `README.md`.
  - Not required to apply — the artifact is the signal.
- `README.md` — hero section, Mermaid architecture diagram, quickstart, MITRE coverage table, eval results excerpt, design decisions, "how to talk about it".
- `ARCHITECTURE.md` — deeper design: why DuckDB, why Sigma, why a custom evaluator, why `cdp/` not `platform/`, data flow diagram.
- Tag `v0.1.0` (manual step you can run when ready).

**Acceptance criteria**
- README renders cleanly on GitHub (you'll verify visually).
- Architecture diagram is included as Mermaid (no binary image dependency).

**Files touched**: `infra/terraform/*`, `README.md`, `ARCHITECTURE.md`.

---

## Current state

_Updated at each checkpoint._

- **Active phase**: — (awaiting approval to start Phase 2)
- **Last checkpoint**: Phase 1 ✅ — ingest + store verified end-to-end.
- **Environment**: Python 3.12.13 via `python3.12` (Homebrew). Project venv at `.venv/`. Installed in editable mode with dev extras.
- **Files present (Phases 0–1)**: `pyproject.toml`, `.gitignore`, `LICENSE`, `.env.example`, `BUILD_PLAN.md`, `README.md`, `data/.gitkeep`, `evals/reports/.gitkeep`, `cdp/__init__.py`, `cdp/models.py`, `cdp/config.py`, `cdp/store.py`, `cdp/ingest.py`, `cdp/cli.py`.
- **Note**: `README.md` is intentionally minimal — project description + a single Run section with verified copy-pasteable Docker commands.
- **Docker setup added**: `Dockerfile` (python:3.12-slim, editable install), `docker-compose.yml` (single `cdp` service, bind-mounts `./cdp` and `./data`), `.dockerignore`. Container sidesteps the macOS `.pth`-hidden issue entirely (Linux filesystem). Verified end-to-end: `docker compose build` → `docker compose run --rm cdp cdp version` → `docker compose run --rm cdp cdp ingest --synthetic` (529 events, 3 Parquet files land on host) → `docker compose run --rm cdp python -c "..."` query returns the planted T1110 burst (50 failures from `185.220.101.45`).
- **Generated artifacts**: `data/{windows_process_creation,authentication,aws_cloudtrail}.{jsonl,parquet}`.
- **Phase 1 verification results**:
  - 529 total events across 3 tables (153 / 200 / 176).
  - 53 admin failed-login events (50 brute-force + 3 noise).
  - 1 encoded-PowerShell event, 1 AttachUserPolicy event, 25 large-GetObject events.
- **Bug fixes during Phase 1**: DuckDB does not accept `?` prepared-parameters inside `COPY ... TO` or `CREATE VIEW`. Replaced with validated table-name + escaped-path interpolation in `cdp/store.py` and the relation-API `write_parquet` in `cdp/ingest.py`.
- **Code-review cleanup applied (post Phase 1)**:
  - `cdp/ingest.py` — `_benign_windows` now produces valid RFC-4122 UUIDv5 ProcessGuids (was raw 128-bit ints with no version/variant); ruff UP017 fixed by switching to `datetime.UTC` alias.
  - `cdp/config.py` — `Settings.load()` now calls `dotenv.load_dotenv(find_dotenv(usecwd=True))` so `.env` files are picked up automatically.
  - `pyproject.toml` — `python-dotenv>=1.0` promoted to a direct dep; mypy tightened (`disallow_untyped_defs = true`, `warn_return_any`, `check_untyped_defs`); ruff `B008` per-file-ignored for `cdp/cli.py` (Typer's documented pattern). Tests subpackage exempted from strict-typing override.
  - `ruff check cdp/` and `mypy cdp/` are both green on 6 source files.
- **Known environmental issue (macOS, not a code bug)**: macOS adds the `com.apple.provenance` xattr to files written under `~/Desktop/...` and asynchronously sets the `UF_HIDDEN` flag on `.pth` files in `site-packages`. Python's `site.py` then logs `Skipping hidden .pth file:` and the editable install becomes invisible (`ModuleNotFoundError: No module named 'cdp'`). Workaround: run `chflags nohidden .venv/lib/python3.12/site-packages/*.pth` immediately before invoking `cdp` or any Python that needs the package. The flag re-applies after a few seconds, so chain it into the same shell command. Linux CI is unaffected.
- **Next action**: await your approval to start Phase 2 (Detection engine: Sigma parser + 6 rules).
