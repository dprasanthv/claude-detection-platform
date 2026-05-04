"""Thin DuckDB wrapper over Parquet telemetry — our analyst-style query layer."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import duckdb

from cdp.config import Settings

_TABLE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class Store:
    """Loads Parquet telemetry files as DuckDB views and runs SQL against them."""

    def __init__(self, data_dir: Path | str | None = None) -> None:
        settings = Settings.load()
        self.data_dir = Path(data_dir).expanduser().resolve() if data_dir else settings.data_dir
        self.con = duckdb.connect(":memory:")
        self._loaded: dict[str, Path] = {}

    def load_parquet(self, name: str, path: Path | str | None = None) -> None:
        """Register a Parquet file as a named view."""
        if not _TABLE_NAME_RE.match(name):
            raise ValueError(f"invalid table name: {name!r}")
        target = Path(path) if path else self.data_dir / f"{name}.parquet"
        if not target.exists():
            raise FileNotFoundError(f"parquet not found: {target}")
        # DuckDB does not support ? parameters inside CREATE VIEW, so quote
        # the path inline (escaping single quotes) and validate the table name.
        safe_path = str(target).replace("'", "''")
        self.con.execute(
            f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM read_parquet('{safe_path}')"
        )
        self._loaded[name] = target

    def load_all(self) -> list[str]:
        """Register every *.parquet file in the data dir. Returns the list of table names."""
        if not self.data_dir.exists():
            return []
        loaded: list[str] = []
        for parquet in sorted(self.data_dir.glob("*.parquet")):
            name = parquet.stem
            self.load_parquet(name, parquet)
            loaded.append(name)
        return loaded

    def query(self, sql: str, params: list[Any] | None = None) -> list[dict[str, Any]]:
        """Execute SQL and return rows as list[dict]."""
        result = self.con.execute(sql, params or [])
        description = result.description or []
        cols = [d[0] for d in description]
        return [dict(zip(cols, row, strict=True)) for row in result.fetchall()]

    def tables(self) -> list[str]:
        return sorted(self._loaded.keys())

    def close(self) -> None:
        self.con.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
