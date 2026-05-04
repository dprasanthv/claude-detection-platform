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
| 2 | Detection engine | Sigma parser → DuckDB SQL, 6+ rules across 4 ATT&CK tactics | ✅ |
| 3 | Claude AI layer | Triage + enrichment + playbook generation, mock fallback | ✅ |
| 4 | API + CLI | FastAPI service, Typer CLI for end-to-end demo | ⬜ |
| 5 | Eval harness | Ground-truth YAML, triage eval, markdown report | ⬜ |
| 6 | Tests | pytest suite (sigma, engine, store, ingest, models, cli) + `cdp validate` | ✅ |
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
- `cdp/prompts.py` — system prompts for triage and playbook (with explicit prompt-injection mitigation), tool-use JSON schemas, and `render_alert_context()` (stable structured rendering for prompt input).
- `cdp/triage.py`
  - `Triager` Protocol with two implementations:
    - `MockTriager` — deterministic heuristic on severity + keyword hits + IP + asset criticality. Stable baseline for the Phase 5 eval.
    - `ClaudeTriager` — Anthropic SDK with forced tool-use (`tool_choice={"type": "tool", "name": "report_triage"}`) and Pydantic validation on the tool output.
  - `make_triager(settings)` factory selects on `ANTHROPIC_API_KEY` presence.
- `cdp/enrich.py`
  - `enrich_alert(alert, asset_db)` — IP private/public/loopback/invalid classification via `ipaddress` stdlib; threat-intel lookup for public IPs; asset DB lookup keyed by `hostname` (Windows/auth) or `userIdentity_userName` (AWS).
  - `load_asset_db(path)` — loads + validates the YAML DB.
  - `enriched_for(alert, …)` — convenience bundle.
- `cdp/playbook.py`
  - `MockPlaybookGenerator` — per-rule templated playbooks (one tailored template per shipped Sigma rule + a generic fallback). Templates are rendered through a safe `format_map` so missing event fields surface as readable `(unknown …)` strings, not crashes.
  - `ClaudePlaybookGenerator` — same SDK plumbing as triage but with a different tool schema (`title`, `summary`, 5–8 `steps`).
  - `make_playbook_generator(settings)` factory.
- `enrichment/assets.yaml` — host + IAM-user records anchored to the synthetic dataset (so the demo's enrichment is *real*), plus a `known_bad_ips` block listing the planted attacker IP as a Tor-exit-node intel hit.
- CLI: `cdp enrich`, `cdp triage`, `cdp playbook`. All three accept `--alert-json FILE`, stdin (`cdp detect --format json | cdp triage --mock`), or `--alert-id ID` (re-runs detection to find a single alert). All have a `--mock` flag to force the offline path even when a key is set.

**Acceptance criteria**
- With `ANTHROPIC_API_KEY` unset, `cdp triage` returns a valid `TriageResult` via the mock. ✅
- With a key set, the SDK plumbing is unit-tested via a stubbed `anthropic` module that returns a synthetic `tool_use` block; the resulting `TriageResult`/`Playbook` is Pydantic-validated. A live API call is intentionally out of scope for the test suite (would break hermeticity); the integration is exercisable manually with `ANTHROPIC_API_KEY=… cdp triage --alert-json …`. ✅
- Playbook output has 5-8 steps and propagates the rule's MITRE techniques. ✅
- All three CLI commands work end-to-end against the synthetic dataset, including the pipe pattern `cdp detect --format json | cdp triage --mock`. ✅

**Files touched**: `cdp/prompts.py`, `cdp/enrich.py`, `cdp/triage.py`, `cdp/playbook.py`, `cdp/models.py` (extracted `AssetCriticality` Literal), `cdp/cli.py` (+`enrich`, `triage`, `playbook`), `enrichment/assets.yaml`, `Dockerfile` (+`COPY enrichment/`), `docker-compose.yml` (+`./enrichment` bind-mount).

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

## Phase 6 — Tests

**Goal**: lock in correctness for everything Phases 0–2 deliver, so subsequent phases can refactor without fear.

**Scope note**: GitHub Actions / CI workflow files are intentionally **out of scope** per project preference. The `cdp validate` subcommand and a `pytest` invocation cover the same checks locally; wiring them into a CI provider is left as an exercise (any of GitHub Actions, GitLab CI, or a pre-commit hook would map straightforwardly to the same commands).

**Deliverables**
- `tests/conftest.py` — shared fixtures: per-test `tmp_data_dir` with `CDP_DATA_DIR` redirected and `ANTHROPIC_API_KEY` scrubbed; session-cached `synthetic_dataset_dir` (one ingest per session, copied into per-test dirs); `seeded_store` (DuckDB pre-loaded); `detections_dir` pointing at the repo's rules.
- `tests/test_models.py` — Pydantic invariants: severity enum, `mitre_techniques` extraction, `TriageResult.confidence` bounds, verdict enum.
- `tests/test_store.py` — DuckDB load + query roundtrip, invalid table-name rejection, missing-file handling, context-manager close, parameterized queries.
- `tests/test_ingest.py` — synthetic determinism (byte-for-byte JSONL equality across runs), planted-attack invariants (T1110 = 50, T1059.001 = 1, T1543.003 = 1, T1078 = 1, T1567.002 = 25), `load_mordor` raises NotImplementedError.
- `tests/test_sigma.py` — `resolve_table` parametrized, every shipped rule parses + validates, every modifier (`contains|startswith|endswith|re|gt|gte|lt|lte`) compiles, list-value OR expansion, condition grammar (`and`/`or`/`not`/parens/`1 of pat`/`all of them`), structural-error paths.
- `tests/test_engine.py` — exact per-rule alert counts pinned (50/1/1/2/1/25 = 80 total), all four required ATT&CK tactics fire, alert-id determinism + format, rule-metadata propagation, unmapped-logsource and missing-table rules silently skipped, `run_all` auto-bootstraps rules + tables.
- `tests/test_cli.py` — Typer `CliRunner` smoke tests over `version`, `ingest`, `detect` (json + table + invalid format + no-data path), `validate` (pass/fail/strict/missing dir/empty dir).
- `cdp/cli.py` — added `cdp validate` subcommand: parses + compiles every rule, shows a summary table, exits non-zero on failure. `--strict` upgrades unmapped-logsource warnings to failures.

**Acceptance criteria**
- `pytest` passes locally with the synthetic dataset (no network, no API key required).
- `cdp validate` exits 0 against `detections/` and exits 1 against intentionally broken rules.
- `ruff check cdp tests` and `mypy cdp` are both green.

**Files touched**: `tests/conftest.py`, `tests/test_models.py`, `tests/test_store.py`, `tests/test_ingest.py`, `tests/test_sigma.py`, `tests/test_engine.py`, `tests/test_cli.py`, `cdp/cli.py` (added `validate`).

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

- **Active phase**: — (Phase 3 ✅; awaiting direction on Phase 4 / Phase 5 / Phase 7).
- **Last checkpoint**: Phase 3 ✅ — Claude AI layer (triage + enrichment + playbook) with deterministic offline mock; SDK plumbing unit-tested via stubbed `anthropic` module; `cdp enrich`, `cdp triage`, `cdp playbook` subcommands added.
- **Previous checkpoint**: Phase 6 ✅ — pytest suite covers sigma/engine/store/ingest/models/cli; `cdp validate` subcommand added. GitHub Actions CI dropped per project preference (see Phase 6 scope note).
- **Earlier checkpoint**: Phase 2 ✅ — Sigma parser, detection engine, 6 rules across 4 ATT&CK tactics verified end-to-end.
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
- **Phase 2 verification results** (run on the synthetic dataset, in Docker):
  - **6/6 rules parse cleanly** under `cdp.sigma.parse_rule_file`.
  - **80 alerts emitted** across 6 distinct rules and 4 ATT&CK tactics.
  - Tactics fired: `credential_access`, `execution`, `persistence`, `exfiltration` (all four required tactics).
  - Per-rule counts: `brute_force_admin_login=50`, `iam_admin_policy_attached=1`, `office_spawns_script_host=2`, `powershell_encoded_command=1`, `s3_large_object_egress=25`, `new_service_install=1`. The Office→encoded-PowerShell event correctly matches *both* `office_spawns_script_host` and `powershell_encoded_command` — overlapping coverage is desired in real detection engineering.
  - `ruff check cdp/` and `mypy cdp/` both green on 8 source files (was 6 in Phase 1; +`sigma.py`, +`engine.py`).
- **Phase 2 design notes**:
  - Sigma subset implemented: equality + `contains|startswith|endswith|re|gt|gte|lt|lte` modifiers, list values OR-expanded, condition grammar with `and`/`or`/`not`/parens/`1 of <pat>`/`all of <pat>`/`them`. Out of scope: aggregations, `near`, `timeframe`, base64offset/utf16 transforms (documented in `detections/README.md`).
  - Logsource resolution table in `cdp.sigma.LOGSOURCE_MAP` is a whitelist (3 entries) so the resolved table name is safe to inline into the generated SQL. All field values flow through DuckDB `?` parameters; no string interpolation of user data.
  - Alert ids are deterministic: `f"{rule.id}-{sha256(matched_event)[:12]}"`. Same dataset → same alert ids, so Phase 5 ground-truth labels stay stable across runs.
  - During mypy fixup, walrus operator was used inside `_parse_or` / `_parse_and` so the type checker can narrow `Optional[Token]` after the short-circuit, and `level` is `cast(SeverityLevel, ...)` because Pydantic enforces the literal at runtime.
- **Files added in Phase 2**: `cdp/sigma.py`, `cdp/engine.py`, `detections/credential_access/{brute_force_login,suspicious_iam_policy_change}.yml`, `detections/execution/{powershell_encoded_command,unusual_process_lineage}.yml`, `detections/persistence/new_service_install.yml`, `detections/exfiltration/unusual_s3_data_egress.yml`, `detections/README.md`. Modified: `cdp/cli.py` (+`cdp detect`), `Dockerfile` (+`COPY detections/`), `docker-compose.yml` (+`./detections:/app/detections` bind mount).
- **Phase 6 design notes**:
  - Test suite is hermetic: no network calls, no Anthropic API key required, no writes to the repo's real `data/` directory. The `tmp_data_dir` fixture monkeypatches `CDP_DATA_DIR` per test and scrubs `ANTHROPIC_API_KEY` so any future code path that calls `Settings.load()` is automatically isolated.
  - Synthetic dataset is generated **once per pytest session** (`synthetic_dataset_dir`, session-scoped) and copied into per-test dirs via `shutil.copy2`. Cheap and fast; the JSONL byte-for-byte determinism test (`test_generate_synthetic_is_deterministic`) is what guarantees this is safe.
  - `tests/test_engine.py` pins **exact** per-rule alert counts (50/1/1/2/1/25 = 80) rather than soft floors. Anyone changing the dataset, rules, or engine semantics has to update the constant on purpose — that's the point.
  - `tests/test_ingest.py::test_no_benign_admin_failures_from_external_ips` is a *cross-cutting* test: it pins an invariant the brute-force rule depends on (only the planted attack IP fires the `not internal_ranges` filter). Without it, dataset drift could silently inflate the brute-force alert count.
  - `cdp validate` was added (instead of a `scripts/validate_rules.py` one-off) to give rule authors a usable local command and to keep the test surface focused on the public CLI rather than internal helpers.
- **Phase 6 verification results** (Docker container, repeatable):
  - `docker compose run --rm cdp pytest -q` — **87 passed** in ~6s.
  - `docker compose run --rm cdp pytest --cov=cdp --cov-report=term` — **97% line coverage** (590 stmts / 19 missed). Per-module: `__init__.py` 100%, `models.py` 100%, `store.py` 100%, `ingest.py` 100%, `cli.py` 97%, `sigma.py` 97%, `config.py` 95%, `engine.py` 86%.
  - `docker compose run --rm cdp ruff check cdp tests` — **All checks passed** on `cdp/` (8 files) + `tests/` (7 files).
  - `docker compose run --rm cdp mypy cdp` — **Success: no issues found in 8 source files**.
  - `docker compose run --rm cdp cdp validate` — **6 / 6 rules valid**, 0 skipped, 0 failed.
- **Lint fixes applied during Phase 6 verification**:
  - `cdp/cli.py` — removed unused `# noqa: BLE001` directive (BLE rules aren't selected in `pyproject.toml`, so the directive was dead code per `RUF100`).
  - `tests/test_engine.py`, `tests/test_sigma.py` — flipped Yoda comparisons (`SIM300`).
  - `tests/test_ingest.py`, `tests/test_sigma.py` — `ruff --fix` reorganized import blocks (`I001`).
  - `tests/test_ingest.py` — replaced ambiguous `×` (multiplication sign) with `*` in a comment (`RUF003`).
- **Files added in Phase 6**: `tests/conftest.py`, `tests/test_models.py`, `tests/test_store.py`, `tests/test_ingest.py`, `tests/test_sigma.py`, `tests/test_engine.py`, `tests/test_cli.py`. Modified: `cdp/cli.py` (+`cdp validate` subcommand).
- **Phase 3 design notes**:
  - **Two layers, one Protocol**: `cdp/triage.py` and `cdp/playbook.py` each define a Protocol (`Triager`, `PlaybookGenerator`) with two implementations (`Mock*` and `Claude*`) and a factory (`make_*`). Callers hold the Protocol; the factory chooses based on `Settings.has_anthropic_key`. This is what lets Phase 5's eval harness run *both* implementations against the same ground truth and report comparable metrics.
  - **Forced tool-use for structured output**: The Claude path uses `tool_choice={"type": "tool", "name": "report_triage"}` (and `submit_playbook` for playbooks). This is the most reliable structured-output mechanism Anthropic offers — Claude *must* emit a single `tool_use` block whose `input` is server-side-validated against our JSON schema. The fallback path (no tool block emitted) raises `RuntimeError` rather than silently fabricating a verdict.
  - **Prompt-injection mitigation**: System prompts explicitly instruct Claude to treat `MATCHED EVENT` / `CONTEXT EVENTS` / `ENRICHMENT` content as untrusted data. The `render_alert_context` helper wraps user-controlled fields in clearly delimited sections and never interpolates them into the system prompt.
  - **Mock heuristic is intentionally simple**: `MockTriager` uses severity floor + keyword bumps + IP + criticality bumps. The point is *not* to be SOTA — it's to be a stable, deterministic baseline so the Phase 5 eval can measure Claude's lift over a non-LLM heuristic (the "is this AI worth the cost?" question every reviewer wants answered).
  - **Templated playbooks anchored to shipped rules**: Each of the 6 Sigma rules has a tailored playbook template (`_TEMPLATES` in `cdp/playbook.py`) referencing fields from the actual matched-event schema (`hostname`, `ParentImage`, `userIdentity_userName`, etc.). Missing fields fall back to readable `(unknown …)` strings via a `_SafeFormatDict.__missing__` override — no `KeyError` crashes on incomplete events.
  - **Asset DB pinned to synthetic dataset**: `enrichment/assets.yaml` lists every host (`WKST-ALICE-01`, `SRV-DB-01`, `AUTH-SVC-01`, …) and IAM user (`dev-bob`, `ops-carol`, …) that the synthetic ingest emits, so the demo's enrichment is real, not theatre. The planted attacker IP `185.220.101.45` is also in the `known_bad_ips` block so it triggers the threat-intel path.
  - **Hermetic SDK testing**: `tests/test_triage.py` and `tests/test_playbook.py` use `unittest.mock.patch.dict("sys.modules", {"anthropic": _StubAnthropicSDK})` to replace the Anthropic SDK with a stub that returns canned `tool_use` blocks. This exercises the same code path real Claude would hit (including the tool-block-extraction loop and the "no tool emitted" failure mode) without network calls or API keys.
- **Phase 3 verification results** (Docker container, repeatable):
  - `docker compose run --rm cdp pytest -q` — **157 passed** in ~7s (was 87 before Phase 3; +70 tests for prompts/enrich/triage/playbook/cli).
  - `docker compose run --rm cdp pytest --cov=cdp` — **97% line coverage** (894 stmts / 29 missed). New modules: `prompts.py` 100%, `triage.py` 100%, `enrich.py` 99%, `playbook.py` 96%; `cli.py` dropped from 97% to 94% (new stdin-handling and SDK-dispatch paths).
  - `docker compose run --rm cdp ruff check cdp tests` — **All checks passed** (12 source files + 11 test files).
  - `docker compose run --rm cdp mypy cdp` — **Success: no issues found in 12 source files**.
  - `docker compose run --rm cdp cdp validate` — **6 / 6 rules valid**, 0 failed.
  - **End-to-end smoke**: `cdp ingest --synthetic | cdp detect --format json | jq '.[] | select(.rule_id=="cdp.exfiltration.s3_large_object_egress") | .[:1]' | cdp triage --mock` correctly produces `verdict=true_positive`, `confidence=0.80` (severity high 0.70 + public IP 0.05 + high-criticality asset 0.05), references the asset owner from the YAML DB, and includes the planted Tor-exit-node country.
  - **Playbook smoke**: same pipe with the new-service-install rule produces a 7-step playbook with the actual `SRV-DB-01` hostname in the title, `svc_sql` user in the summary, `cmd.exe` parent process in the steps, and `data-platform@corp.example` notification target from the asset DB. No unfilled `{placeholder}` strings.
- **Phase 3 lint fixes during verification**:
  - Annotated 3 mutable class-level dicts with `ClassVar` (`RUF012`) — `MockTriager.SEVERITY_FLOOR`, `MockTriager.SUSPICIOUS_KEYWORDS` (tuple promoted from raw class var to `ClassVar[tuple[…]]`), and the 2 SDK-stub `last_create_kwargs` dicts in tests.
  - Removed unused `# noqa: N802` directives from the SDK stub `Anthropic` factory methods (the `N` ruleset isn't selected; the directives were dead code per `RUF100`).
  - Replaced `# type: ignore[type-arg]` on `_SafeFormatDict(dict)` with a properly parameterized `dict[str, str]` base. mypy is happier; reader is happier.
- **Files added in Phase 3**: `cdp/prompts.py`, `cdp/enrich.py`, `cdp/triage.py`, `cdp/playbook.py`, `enrichment/assets.yaml`, `tests/test_prompts.py`, `tests/test_enrich.py`, `tests/test_triage.py`, `tests/test_playbook.py`. Modified: `cdp/models.py` (extracted `AssetCriticality` Literal type alias), `cdp/cli.py` (+`enrich`, `triage`, `playbook` subcommands and shared `_load_alerts` / `_resolve_alerts` helpers), `tests/test_cli.py` (+ Phase 3 subcommand tests), `Dockerfile` (+`COPY enrichment/`), `docker-compose.yml` (+`./enrichment` bind-mount), `BUILD_PLAN.md`, `README.md`.
- **Next action**: await your direction on Phase 4 (FastAPI service + `cdp demo`), Phase 5 (eval harness), or Phase 7 (README polish + architecture docs + Terraform).
