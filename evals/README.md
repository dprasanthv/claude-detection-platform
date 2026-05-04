# Phase 5 — Eval harness

This directory measures how well a triager (the offline mock or real Claude) classifies alerts from the synthetic dataset, against a hand-labeled ground truth.

The eval is the project's most important differentiator: it answers the "is this LLM use actually working?" question with numbers, not adjectives.

## Files

| File | What it is |
|---|---|
| `ground_truth.yaml` | 20 hand-labeled alerts (14 TP / 6 FP) anchored to the deterministic synthetic dataset (`cdp/ingest.py`). Each row has `alert_id`, `rule_id`, `verdict`, and a one-sentence `rationale`. |
| `run_eval.py` | The harness. Loads the ground truth, re-runs ingest + detection + enrichment + triage, computes metrics, and writes both a Markdown and a JSON report under `reports/`. Importable as a library (`from evals.run_eval import run, compute_mode_metrics, …`). |
| `_build_ground_truth.py` | One-shot generator for `ground_truth.yaml`. Re-run after any change to `cdp/ingest.py` that would shift alert IDs. |
| `reports/seed-run.md` | A pre-generated mock-only run that ships in the repo so a reader can see the eval shape without an Anthropic API key. |
| `reports/seed-run.json` | Same data as the Markdown above, machine-readable. |

## How to run

```bash
# Mock-only (default; works without ANTHROPIC_API_KEY).
docker compose run --rm cdp cdp eval --mock

# Real Claude (requires ANTHROPIC_API_KEY in env or .env).
docker compose run --rm cdp cdp eval --claude

# Both side-by-side, written to the same report.
docker compose run --rm cdp cdp eval --both

# Direct invocation (same flags), useful in CI / scripted contexts.
docker compose run --rm cdp python evals/run_eval.py --mock --out-name latest
```

Both the Markdown and JSON reports land under `evals/reports/`. Filenames default to `latest.{md,json}`; pass `--out-name foo` to write `foo.{md,json}` instead.

## Methodology

### Ground truth

Labels are binary — `true_positive` or `false_positive`. They reflect what a competent SOC analyst would conclude after reading the matched event plus the static enrichment our `cdp/enrich.py` attaches (IP class, asset criticality, threat-intel hits).

The synthetic dataset has two deliberate FP traps to give the eval signal:

1. **Coffee-shop brute-force** — 6 admin failures from a public-but-unflagged IP (`198.51.100.10`, TEST-NET-2), immediately followed by a successful login. The Sigma rule's `not internal_ranges` filter doesn't catch it, but the small burst + absent threat-intel hit + immediate auth success is a classic "forgot the password" pattern.
2. **Internal analytics-export S3 egress** — 3 large `GetObject` calls by `dev-alice` from an internal AWS-VPC IP into a known-good `acme-analytics-exports` bucket. Looks exfil-shaped to the rule, but the user / IP / bucket combination is sanctioned.

Both scenarios live in `cdp/ingest.py` under `_benign_but_rule_firing_*`.

### Collapse modes

Every triager prediction is one of three values: `true_positive`, `false_positive`, or `needs_investigation`. Ground truth is binary, so we report two collapse modes in parallel:

- **`strict`** — `needs_investigation` counts as *wrong* (i.e., "didn't produce a confident actionable verdict"). Harshest judgement.
- **`lenient`** — `needs_investigation` is folded into `true_positive` (i.e., "the analyst will look at it"). Reflects the SOC reality where escalation alone is often the right outcome.

### Metrics

Per (triager × mode), the report includes:

- **Accuracy** — fraction of correct predictions.
- **TP-class precision/recall/F1** — treating `true_positive` as the positive label. Answers "how reliably does the triager catch real attacks?"
- **FP-class precision/recall/F1** — treating `false_positive` as the positive label. Answers "how reliably does the triager *suppress* false positives?"
- **3-way confusion matrix** — rows are ground truth, columns are the raw verdict (TP/FP/NI). Lets a reader see *why* a metric is low without re-running.
- **Per-rule accuracy** — same metric broken down by `rule_id`. Surfaces rules where the triager systematically misses (e.g. the synthetic FP-rich rules).
- **Disagreement list** — every wrong prediction with the ground-truth rationale and the triager's own reasoning side-by-side.

## Caveats

- **Sample size is small.** 20 alerts isn't enough to make confident claims about real-world performance. The point is *the harness*, not the headline number — the same code runs against a 200-alert real corpus the moment one exists.
- **Mock triager is intentionally dumb.** Its job is to be a stable baseline so Claude's *lift* is visible. Mock currently scores 0% on FP-class recall (it always flags severity ≥ high as TP) — that's not a bug, it's the floor we want to beat.
- **Synthetic data is synthetic.** The FP traps are "obviously benign once you read the context." Real SOC ambiguity is messier; expect a real-corpus eval to show lower numbers across the board.
- **Determinism.** Mock runs are bit-for-bit deterministic given the dataset seed. Claude runs are not — the same prompt can produce different reasoning text and (rarely) different verdicts. Run the same eval 3-5 times to see variance before drawing conclusions.

## Reproducing the seed run

```bash
docker compose run --rm cdp cdp eval --mock --out-name seed-run
git diff evals/reports/seed-run.md
# expect zero diff (mock is deterministic given the seed)
```

If `seed-run.md` differs from what's checked in, either `cdp/ingest.py` shifted the synthetic dataset (and `ground_truth.yaml` needs regenerating via `python evals/_build_ground_truth.py`) or the `MockTriager` heuristic was tuned. Both are deliberate code changes; the diff is the audit log.
