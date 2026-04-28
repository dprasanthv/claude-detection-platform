"""Typer CLI for claude-detection-platform.

Subcommands grow as phases land. Current:
- ``cdp ingest`` — Phase 1, synthetic or Mordor telemetry → Parquet.
- ``cdp detect`` — Phase 2, run Sigma rules against the store, emit Alerts.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from cdp.config import Settings
from cdp.engine import DEFAULT_RULES_DIR, DetectionEngine
from cdp.ingest import generate_synthetic_dataset, load_mordor
from cdp.store import Store

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
def version() -> None:
    """Print the installed package version."""
    import cdp

    console.print(cdp.__version__)


if __name__ == "__main__":
    app()
