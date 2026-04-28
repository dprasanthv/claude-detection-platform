# Detections

Sigma rules consumed by `cdp detect`. Each rule compiles to a parameterized DuckDB query against one of three telemetry tables: `windows_process_creation`, `authentication`, `aws_cloudtrail`.

## MITRE ATT&CK coverage

| Rule file | ATT&CK technique | Tactic | Severity | Logsource → table |
|---|---|---|---|---|
| `credential_access/brute_force_login.yml` | T1110 — Brute Force | credential_access | high | `category=authentication` → `authentication` |
| `credential_access/suspicious_iam_policy_change.yml` | T1078 — Valid Accounts | credential_access | critical | `product=aws, service=cloudtrail` → `aws_cloudtrail` |
| `execution/powershell_encoded_command.yml` | T1059.001 — PowerShell | execution | high | `product=windows, category=process_creation` → `windows_process_creation` |
| `execution/unusual_process_lineage.yml` | T1059 — Command/Script Interpreter | execution | high | `product=windows, category=process_creation` → `windows_process_creation` |
| `persistence/new_service_install.yml` | T1543.003 — Windows Service | persistence | high | `product=windows, category=process_creation` → `windows_process_creation` |
| `exfiltration/unusual_s3_data_egress.yml` | T1567.002 — Exfiltration to Cloud Storage | exfiltration | high | `product=aws, service=cloudtrail` → `aws_cloudtrail` |

Four ATT&CK tactics are covered (credential_access, execution, persistence, exfiltration), satisfying the Phase 2 acceptance criterion.

## Authoring a new rule

A rule file is YAML with this minimum shape:

```yaml
title: <human readable title>
id: <stable slug or UUID>
status: test            # test | experimental | stable
level: high             # informational | low | medium | high | critical
logsource:              # one of the supported (product, service, category) tuples below
  product: windows
  category: process_creation
detection:
  selection:            # any name; multiple selections allowed
    Image|endswith: \powershell.exe
  encoded:
    CommandLine|contains: ' -EncodedCommand '
  condition: selection and encoded
tags:
  - attack.execution
  - attack.t1059.001
```

### Logsource → table mapping

`cdp/sigma.py::LOGSOURCE_MAP` resolves a Sigma `logsource` block to a concrete table. A rule whose logsource does not resolve is skipped at runtime (not an error).

| Sigma logsource | Resolves to |
|---|---|
| `product: windows, category: process_creation` | `windows_process_creation` |
| `product: aws, service: cloudtrail` | `aws_cloudtrail` |
| `category: authentication` | `authentication` |

### Supported field modifiers

Postfix after `|` on a field name. Default (no modifier) is equality, with both sides cast to `VARCHAR` so YAML scalars compare uniformly.

| Modifier | Meaning | Compiled SQL |
|---|---|---|
| _(none)_ | equality | `CAST("field" AS VARCHAR) = ?` |
| `contains` | substring | `... LIKE '%value%'` |
| `startswith` | prefix | `... LIKE 'value%'` |
| `endswith` | suffix | `... LIKE '%value'` |
| `re` | regex | `regexp_matches(CAST("field" AS VARCHAR), ?)` |
| `gt`, `gte`, `lt`, `lte` | numeric compare | `"field" > ?` (no cast) |

A list value is OR-expanded:
```yaml
Image|endswith:
  - \powershell.exe
  - \cmd.exe
```
becomes `(... LIKE '%\\powershell.exe' OR ... LIKE '%\\cmd.exe')`.

### Condition grammar

Supported tokens: selection names, `and`, `or`, `not`, parentheses, `1 of <pattern>`, `all of <pattern>`, `them` (alias for `*`). Patterns use shell-glob style (`fnmatch`).

```text
condition: selection and not internal_ranges
condition: 1 of selection_*
condition: all of them
condition: (a or b) and not c
```

### Out of scope (intentionally)

To keep the parser auditable for the demo, these Sigma features are **not** supported: aggregations (`| count() by ...`), `near` correlation, `timeframe` windows, base64offset / utf16 transforms. Adding them is incremental work but blows up the parser surface area.

## Validating a rule

Every rule under `detections/` is parsed and compiled at the start of every `cdp detect` run. To validate without running detections:

```python
from pathlib import Path
from cdp.sigma import parse_rule_file, validate_rule

rule = parse_rule_file(Path("detections/execution/powershell_encoded_command.yml"))
validate_rule(rule)  # raises on any structural problem
```

## Expected alert volume against the synthetic dataset

The deterministic synthetic dataset (`cdp ingest --synthetic`) plants one attack scenario per rule. Approximate counts after a clean run:

| Rule | Alerts |
|---|---|
| `cdp.credential_access.brute_force_admin_login` | ~50 (one per failed admin login from the planted public IP) |
| `cdp.credential_access.iam_admin_policy_attached` | 1 |
| `cdp.execution.powershell_encoded_command` | 1 |
| `cdp.execution.office_spawns_script_host` | 1 |
| `cdp.persistence.new_service_install` | 1 |
| `cdp.exfiltration.s3_large_object_egress` | 25 (one per planted large `GetObject`) |
