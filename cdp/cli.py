"""Typer CLI for claude-detection-platform.

Subcommands grow as phases land. Current:
- ``cdp ingest`` — Phase 1, synthetic or Mordor telemetry → Parquet.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from cdp.config import Settings
from cdp.ingest import generate_synthetic_dataset, load_mordor

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
def version() -> None:
    """Print the installed package version."""
    import cdp

    console.print(cdp.__version__)


if __name__ == "__main__":
    app()
