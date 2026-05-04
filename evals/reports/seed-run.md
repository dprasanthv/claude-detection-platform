# Eval report — MockTriager

_Generated: 2026-05-04T02:03:39+00:00_

Ground-truth file: `evals/ground_truth.yaml` (20 alerts)

## Summary

| Triager | Model | Mode | Accuracy | TP precision | TP recall | TP F1 | FP precision | FP recall | FP F1 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| MockTriager | `cdp-mock-triager-v1` | strict | 70.00% (14/20) | 70.00% | 100.00% | 82.35% | 0.00% | 0.00% | 0.00% |
| MockTriager | `cdp-mock-triager-v1` | lenient | 70.00% (14/20) | 70.00% | 100.00% | 82.35% | 0.00% | 0.00% | 0.00% |

## MockTriager (`cdp-mock-triager-v1`)

### Confusion matrix (3-way, strict)

Rows are ground truth; columns are the triager's raw verdict.

| | TP predicted | FP predicted | NI predicted |
|---|---:|---:|---:|
| true_positive | 14 | 0 | 0 |
| false_positive | 6 | 0 | 0 |

### Per-rule accuracy (strict)

| Rule | n | correct | accuracy |
|---|---:|---:|---:|
| `cdp.credential_access.brute_force_admin_login` | 7 | 4 | 57.14% |
| `cdp.credential_access.iam_admin_policy_attached` | 1 | 1 | 100.00% |
| `cdp.execution.office_spawns_script_host` | 2 | 2 | 100.00% |
| `cdp.execution.powershell_encoded_command` | 1 | 1 | 100.00% |
| `cdp.exfiltration.s3_large_object_egress` | 8 | 5 | 62.50% |
| `cdp.persistence.new_service_install` | 1 | 1 | 100.00% |

### Disagreements (strict): 6 of 20

- **`cdp.credential_access.brute_force_admin_login-caabe35b3183`** — truth=`false_positive`, predicted=`true_positive` (confidence 0.75)
  - Ground-truth rationale: Small 6-event admin failure burst from a public-but-unflagged IP, immediately followed by a successful auth — classic 'forgot the password, got it on the 7th try' scenario.
  - Triager reasoning: Rule `cdp.credential_access.brute_force_admin_login` fired at severity `high`. MITRE: T1110. Affected asset has criticality `critical` (owner=corp-it@corp.example).
- **`cdp.credential_access.brute_force_admin_login-5c51efbb2230`** — truth=`false_positive`, predicted=`true_positive` (confidence 0.75)
  - Ground-truth rationale: Small 6-event admin failure burst from a public-but-unflagged IP, immediately followed by a successful auth — classic 'forgot the password, got it on the 7th try' scenario.
  - Triager reasoning: Rule `cdp.credential_access.brute_force_admin_login` fired at severity `high`. MITRE: T1110. Affected asset has criticality `critical` (owner=corp-it@corp.example).
- **`cdp.credential_access.brute_force_admin_login-6460f75b5582`** — truth=`false_positive`, predicted=`true_positive` (confidence 0.75)
  - Ground-truth rationale: Small 6-event admin failure burst from a public-but-unflagged IP, immediately followed by a successful auth — classic 'forgot the password, got it on the 7th try' scenario.
  - Triager reasoning: Rule `cdp.credential_access.brute_force_admin_login` fired at severity `high`. MITRE: T1110. Affected asset has criticality `critical` (owner=corp-it@corp.example).
- **`cdp.exfiltration.s3_large_object_egress-ffd66ede9a16`** — truth=`false_positive`, predicted=`true_positive` (confidence 0.70)
  - Ground-truth rationale: 80MB GetObject of `acme-analytics-exports` by `dev-alice` from an internal AWS-VPC IP — sanctioned nightly analytics export, known-good user/bucket combination.
  - Triager reasoning: Rule `cdp.exfiltration.s3_large_object_egress` fired at severity `high`. MITRE: T1567.002.
- **`cdp.exfiltration.s3_large_object_egress-01e8ec83e5b7`** — truth=`false_positive`, predicted=`true_positive` (confidence 0.70)
  - Ground-truth rationale: 80MB GetObject of `acme-analytics-exports` by `dev-alice` from an internal AWS-VPC IP — sanctioned nightly analytics export, known-good user/bucket combination.
  - Triager reasoning: Rule `cdp.exfiltration.s3_large_object_egress` fired at severity `high`. MITRE: T1567.002.
- **`cdp.exfiltration.s3_large_object_egress-e133c79b7c88`** — truth=`false_positive`, predicted=`true_positive` (confidence 0.70)
  - Ground-truth rationale: 80MB GetObject of `acme-analytics-exports` by `dev-alice` from an internal AWS-VPC IP — sanctioned nightly analytics export, known-good user/bucket combination.
  - Triager reasoning: Rule `cdp.exfiltration.s3_large_object_egress` fired at severity `high`. MITRE: T1567.002.

---

### Methodology notes

- **Ground truth** is hand-labeled by the project author against the deterministic synthetic dataset (`cdp/ingest.py`). Labels are binary (`true_positive` / `false_positive`); see `evals/ground_truth.yaml` for per-alert rationale.
- **Strict mode** counts a `needs_investigation` prediction as wrong. **Lenient mode** counts it as `true_positive` (the analyst will review it).
- **TP-class metrics** treat `true_positive` as the positive label. **FP-class metrics** treat `false_positive` as the positive label (useful when you care about false-positive *recall* — i.e., how many of the FPs the triager correctly suppressed).
- The mock triager is a stable baseline — its job is to make the Claude triager's *lift* visible, not to be SOTA itself.
