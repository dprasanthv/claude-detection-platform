"""Typer CLI for claude-detection-platform.

Subcommands grow as phases land. Current:
- ``cdp ingest`` — Phase 1, synthetic or Mordor telemetry → Parquet.
- ``cdp detect`` — Phase 2, run Sigma rules against the store, emit Alerts.
- ``cdp validate`` — Phase 2, parse + compile every rule (used by CI).
- ``cdp enrich`` — Phase 3, attach static enrichment to one or more alerts.
- ``cdp triage`` — Phase 3, classify alerts via Claude (or the offline mock).
- ``cdp playbook`` — Phase 3, generate IR playbooks via Claude (or the offline mock).
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from cdp.config import Settings
from cdp.engine import DEFAULT_RULES_DIR, DetectionEngine
from cdp.enrich import DEFAULT_ASSET_DB, enrich_alert, load_asset_db
from cdp.ingest import generate_synthetic_dataset, load_mordor
from cdp.models import Alert, EnrichedAlert
from cdp.playbook import MockPlaybookGenerator, make_playbook_generator
from cdp.sigma import compile_rule, load_rules, resolve_table
from cdp.store import Store
from cdp.triage import MockTriager, make_triager

app = typer.Typer(add_completion=False, help="Claude Detection Platform CLI", no_args_is_help=True)
console = Console()


@app.command()
def ingest(
    synthetic: bool = typer.Option(
        True, "--synthetic/--no-synthetic", help="Generate the deterministic synthetic dataset."
    ),
    mordor: str | None = typer.Option(
        None, "--mordor", help="Load a Mordor scenario by name (not implemented in this demo)."
    ),
    data_dir: Path | None = typer.Option(
        None, "--data-dir", help="Override CDP_DATA_DIR for this run."
    ),
) -> None:
    """Generate (or download) telemetry and materialize Parquet files."""
    settings = Settings.load()
    target = (data_dir or settings.data_dir).expanduser().resolve()

    if mordor:
        load_mordor(mordor, target)  # raises NotImplementedError in the demo
        return

    if not synthetic:
        raise typer.BadParameter("nothing to ingest (pass --synthetic or --mordor)")

    stats = generate_synthetic_dataset(target)

    table = Table(title="Ingest complete", show_header=True, header_style="bold cyan")
    table.add_column("Table")
    table.add_column("Events", justify="right")
    for name, count in stats.per_table.items():
        table.add_row(name, str(count))
    table.add_row("[bold]total[/bold]", f"[bold]{stats.total_events}[/bold]")
    console.print(table)
    console.print(f"[green]wrote Parquet files to[/green] {stats.output_dir}")


@app.command()
def detect(
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR, "--rules-dir", help="Directory containing Sigma rule YAML files."
    ),
    fmt: str = typer.Option(
        "table", "--format", "-f", help="Output format: 'table' or 'json'."
    ),
    limit: int = typer.Option(
        0, "--limit", help="Show at most N alerts in table mode (0 = all)."
    ),
) -> None:
    """Run all Sigma rules against the store and print resulting alerts."""
    if fmt not in {"table", "json"}:
        raise typer.BadParameter("--format must be 'table' or 'json'")

    with Store() as store:
        store.load_all()
        if not store.tables():
            console.print(
                "[yellow]No telemetry loaded. Run `cdp ingest --synthetic` first.[/yellow]"
            )
            raise typer.Exit(code=1)

        engine = DetectionEngine(store, rules_dir=rules_dir)
        rules = engine.load_rules()
        alerts = engine.run_all()

    if fmt == "json":
        out = [a.model_dump(mode="json") for a in alerts]
        if limit > 0:
            out = out[:limit]
        typer.echo(json.dumps(out, indent=2, default=str))
        return

    console.print(
        f"[cyan]Loaded {len(rules)} rule(s) from {engine.rules_dir} → "
        f"{len(alerts)} alert(s) emitted.[/cyan]"
    )

    alerts_table = Table(
        title=f"Alerts (showing {min(len(alerts), limit) if limit > 0 else len(alerts)} of {len(alerts)})",
        show_header=True,
        header_style="bold red",
    )
    alerts_table.add_column("rule_id")
    alerts_table.add_column("level")
    alerts_table.add_column("mitre")
    alerts_table.add_column("logsource")
    alerts_table.add_column("matched_at")
    rows = alerts if limit <= 0 else alerts[:limit]
    for a in rows:
        alerts_table.add_row(
            a.rule_id,
            a.rule_level,
            ",".join(a.mitre_techniques) or "-",
            a.logsource_table,
            a.matched_at.isoformat(timespec="seconds"),
        )
    console.print(alerts_table)

    counts = Counter(a.rule_id for a in alerts)
    breakdown = Table(title="Per-rule counts", show_header=True, header_style="bold cyan")
    breakdown.add_column("rule")
    breakdown.add_column("alerts", justify="right")
    for rule_id, count in sorted(counts.items()):
        breakdown.add_row(rule_id, str(count))
    console.print(breakdown)


@app.command()
def validate(
    rules_dir: Path = typer.Option(
        DEFAULT_RULES_DIR, "--rules-dir", help="Directory containing Sigma rule YAML files."
    ),
    strict: bool = typer.Option(
        False,
        "--strict/--no-strict",
        help="Treat rules whose logsource does not resolve to a known table as failures.",
    ),
) -> None:
    """Parse and compile every rule under ``rules_dir``. Non-zero exit on failure.

    Designed for CI and pre-commit hooks: catches malformed YAML, unsupported
    modifiers, condition-grammar errors, and (optionally) unmapped logsources
    before they reach a ``cdp detect`` run.
    """
    target = rules_dir.expanduser().resolve()
    if not target.exists():
        console.print(f"[red]rules dir not found:[/red] {target}")
        raise typer.Exit(code=2)

    rules = load_rules(target)
    if not rules:
        console.print(f"[yellow]no rules found under[/yellow] {target}")
        raise typer.Exit(code=2)

    failures: list[tuple[str, str]] = []
    skipped: list[str] = []
    for rule in rules:
        if resolve_table(rule.logsource) is None:
            if strict:
                failures.append((rule.id, f"unmapped logsource: {rule.logsource}"))
            else:
                skipped.append(rule.id)
            continue
        try:
            compile_rule(rule)
        except Exception as exc:
            failures.append((rule.id, f"{type(exc).__name__}: {exc}"))

    summary = Table(title="Sigma rule validation", show_header=True, header_style="bold cyan")
    summary.add_column("metric")
    summary.add_column("count", justify="right")
    summary.add_row("total", str(len(rules)))
    summary.add_row("passed", str(len(rules) - len(failures) - len(skipped)))
    summary.add_row("skipped (unmapped logsource)", str(len(skipped)))
    summary.add_row("[red]failed[/red]", f"[red]{len(failures)}[/red]")
    console.print(summary)

    if skipped and not strict:
        console.print(f"[dim]skipped (no table mapping): {', '.join(skipped)}[/dim]")

    if failures:
        for rule_id, reason in failures:
            console.print(f"[red]✗ {rule_id}[/red] — {reason}")
        raise typer.Exit(code=1)

    console.print("[green]all rules valid[/green]")


@app.command()
def enrich(
    alert_json: Path | None = typer.Option(
        None,
        "--alert-json",
        help="Read alert(s) from this JSON file. If omitted and stdin is non-empty, "
        "read from stdin. Accepts a single alert object or a list.",
    ),
    asset_db: Path = typer.Option(
        DEFAULT_ASSET_DB, "--asset-db", help="Path to the YAML asset DB."
    ),
) -> None:
    """Attach static enrichment (IP class, asset criticality) to one or more alerts."""
    alerts = _load_alerts(alert_json)
    if not alerts:
        console.print("[yellow]no alerts on input[/yellow]")
        raise typer.Exit(code=1)
    db = load_asset_db(asset_db)
    enrichments = [enrich_alert(a, db).model_dump(mode="json") for a in alerts]
    typer.echo(json.dumps(enrichments, indent=2, default=str))


@app.command()
def triage(
    alert_json: Path | None = typer.Option(None, "--alert-json", help="Path to alert JSON."),
    alert_id: str | None = typer.Option(
        None,
        "--alert-id",
        help="Re-run detection and triage the single alert with this id (uses --rules-dir).",
    ),
    rules_dir: Path = typer.Option(DEFAULT_RULES_DIR, "--rules-dir"),
    asset_db: Path = typer.Option(DEFAULT_ASSET_DB, "--asset-db"),
    use_mock: bool = typer.Option(
        False, "--mock", help="Force the deterministic offline triager."
    ),
    limit: int = typer.Option(
        0, "--limit", help="Triage at most N alerts (0 = all). Useful when piping from `cdp detect`."
    ),
) -> None:
    """Classify one or more alerts as TP / FP / needs_investigation."""
    alerts = _resolve_alerts(alert_json=alert_json, alert_id=alert_id, rules_dir=rules_dir)
    if limit > 0:
        alerts = alerts[:limit]
    if not alerts:
        console.print("[yellow]no alerts to triage[/yellow]")
        raise typer.Exit(code=1)

    db = load_asset_db(asset_db)
    triager = MockTriager() if use_mock else make_triager()

    results = []
    for a in alerts:
        enriched = EnrichedAlert(alert=a, enrichment=enrich_alert(a, db))
        results.append(triager.triage(enriched).model_dump(mode="json"))

    typer.echo(json.dumps(results, indent=2, default=str))


@app.command()
def playbook(
    alert_json: Path | None = typer.Option(None, "--alert-json"),
    alert_id: str | None = typer.Option(
        None,
        "--alert-id",
        help="Re-run detection and generate a playbook for the single alert with this id.",
    ),
    rules_dir: Path = typer.Option(DEFAULT_RULES_DIR, "--rules-dir"),
    asset_db: Path = typer.Option(DEFAULT_ASSET_DB, "--asset-db"),
    use_mock: bool = typer.Option(False, "--mock", help="Force the deterministic offline generator."),
    limit: int = typer.Option(0, "--limit"),
) -> None:
    """Generate a containment + investigation playbook for one or more alerts."""
    alerts = _resolve_alerts(alert_json=alert_json, alert_id=alert_id, rules_dir=rules_dir)
    if limit > 0:
        alerts = alerts[:limit]
    if not alerts:
        console.print("[yellow]no alerts to plan[/yellow]")
        raise typer.Exit(code=1)

    db = load_asset_db(asset_db)
    generator = MockPlaybookGenerator() if use_mock else make_playbook_generator()

    results = []
    for a in alerts:
        enriched = EnrichedAlert(alert=a, enrichment=enrich_alert(a, db))
        results.append(generator.generate(enriched).model_dump(mode="json"))

    typer.echo(json.dumps(results, indent=2, default=str))


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address."),
    port: int = typer.Option(8000, "--port", help="Port."),
    reload: bool = typer.Option(False, "--reload", help="Enable uvicorn auto-reload (dev)."),
    log_level: str = typer.Option("info", "--log-level"),
) -> None:
    """Run the FastAPI service (uvicorn). Leaves the detection pipeline lazy —
    it runs on the first request, not at import time.
    """
    import uvicorn

    uvicorn.run("cdp.api:app", host=host, port=port, reload=reload, log_level=log_level)


@app.command()
def demo(
    claude: bool = typer.Option(
        False, "--claude", help="Use ClaudeTriager/PlaybookGenerator if ANTHROPIC_API_KEY is set."
    ),
    limit: int = typer.Option(3, "--limit", help="Max alerts to triage + playbook."),
) -> None:
    """End-to-end demo: ingest → detect → enrich → triage → playbook → print.

    The one command a reviewer can paste to see every phase working against
    each other. Uses the offline mock triager/playbook generator by default so
    it runs without an Anthropic API key; pass ``--claude`` to use the live
    model when one is available.
    """
    settings = Settings.load()

    console.rule("[bold cyan]1. Ingest")
    stats = generate_synthetic_dataset(settings.data_dir)
    console.print(f"wrote {stats.total_events} events to {stats.output_dir}")

    console.rule("[bold cyan]2. Detect")
    with Store(data_dir=settings.data_dir) as store:
        store.load_all()
        engine = DetectionEngine(store)
        engine.load_rules()
        alerts = engine.run_all()
    console.print(f"produced [bold]{len(alerts)}[/bold] alerts across {len(engine.rules)} rules")

    if not alerts:
        console.print("[yellow]no alerts — nothing to triage[/yellow]")
        return

    console.rule("[bold cyan]3. Enrich")
    db = load_asset_db(DEFAULT_ASSET_DB)
    # Take the highest-severity alerts first so the demo leads with the
    # most interesting output.
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    chosen = sorted(alerts, key=lambda a: severity_order.get(a.rule_level, 5))[:limit]
    enriched_list = [EnrichedAlert(alert=a, enrichment=enrich_alert(a, db)) for a in chosen]
    console.print(f"enriched {len(enriched_list)} alerts")

    using_claude = claude and settings.has_anthropic_key
    if claude and not settings.has_anthropic_key:
        console.print(
            "[yellow]--claude passed but ANTHROPIC_API_KEY is unset; "
            "falling back to offline mock[/yellow]"
        )
    triager = make_triager(settings) if using_claude else MockTriager()
    generator = make_playbook_generator(settings) if using_claude else MockPlaybookGenerator()

    console.rule(f"[bold cyan]4. Triage  [dim]({type(triager).__name__})")
    for ea in enriched_list:
        tr = triager.triage(ea)
        color = {
            "true_positive": "red",
            "needs_investigation": "yellow",
            "false_positive": "green",
        }[tr.verdict]
        console.print(
            f"[bold]{ea.alert.rule_title}[/bold]  → "
            f"[{color}]{tr.verdict}[/] (conf {tr.confidence:.2f})"
        )
        console.print(f"  [dim]{tr.reasoning}[/dim]")

    console.rule(f"[bold cyan]5. Playbook  [dim]({type(generator).__name__})")
    for ea in enriched_list:
        pb = generator.generate(ea)
        console.print(f"[bold]{pb.title}[/bold]")
        for i, step in enumerate(pb.steps, 1):
            console.print(f"  {i}. {step}")
        console.print()

    console.rule("[bold green]Demo complete")


@app.command()
def eval(
    mock: bool = typer.Option(False, "--mock", help="Run MockTriager (default if no flag)."),
    claude: bool = typer.Option(False, "--claude", help="Run ClaudeTriager (requires ANTHROPIC_API_KEY)."),
    both: bool = typer.Option(False, "--both", help="Shorthand for --mock --claude."),
    out_name: str = typer.Option(
        "latest", "--out-name",
        help="Report filename stem written under evals/reports/.",
    ),
    quiet: bool = typer.Option(False, "--quiet"),
) -> None:
    """Run the Phase 5 eval harness against `evals/ground_truth.yaml`.

    Always renders both a Markdown and a JSON report. With no flags, runs the
    offline mock so the command works without an Anthropic API key.
    """
    # `evals/` is a top-level repo directory rather than a subpackage of `cdp`,
    # so the `cdp` console-script's sys.path doesn't include it. Add the repo
    # root explicitly so `import evals.run_eval` resolves.
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from evals.run_eval import main as eval_main

    argv: list[str] = []
    if mock:
        argv.append("--mock")
    if claude:
        argv.append("--claude")
    if both:
        argv.append("--both")
    argv += ["--out-name", out_name]
    if quiet:
        argv.append("--quiet")
    raise typer.Exit(code=eval_main(argv))


@app.command()
def version() -> None:
    """Print the installed package version."""
    import cdp

    console.print(cdp.__version__)


# ---------- shared helpers (Phase 3 onward) ----------


def _load_alerts(alert_json: Path | None) -> list[Alert]:
    """Read alerts from --alert-json file, or stdin if no file given.

    Accepts either a single alert object or a list of alert objects (the
    shape ``cdp detect --format json`` emits).
    """
    if alert_json is not None:
        raw = alert_json.read_text()
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        return []
    if not raw.strip():
        return []
    payload = json.loads(raw)
    items: list[Any] = payload if isinstance(payload, list) else [payload]
    return [Alert.model_validate(item) for item in items]


def _resolve_alerts(
    *,
    alert_json: Path | None,
    alert_id: str | None,
    rules_dir: Path,
) -> list[Alert]:
    """Either look up a single alert by id (via re-running detection) or load from file/stdin."""
    if alert_id:
        with Store() as store:
            store.load_all()
            if not store.tables():
                console.print(
                    "[yellow]No telemetry loaded. Run `cdp ingest --synthetic` first.[/yellow]"
                )
                raise typer.Exit(code=1)
            engine = DetectionEngine(store, rules_dir=rules_dir)
            engine.load_rules()
            alerts = [a for a in engine.run_all() if a.id == alert_id]
        if not alerts:
            console.print(f"[red]no alert with id `{alert_id}` in the latest detection run[/red]")
            raise typer.Exit(code=1)
        return alerts
    return _load_alerts(alert_json)


if __name__ == "__main__":
    app()
