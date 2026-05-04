"""DuckDB store wrapper — load + query roundtrip and validation."""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from cdp.store import Store


@pytest.fixture
def tiny_parquet(tmp_path: Path) -> Path:
    """A two-row Parquet file for fast roundtrip tests."""
    p = tmp_path / "tiny.parquet"
    con = duckdb.connect(":memory:")
    try:
        con.sql("SELECT * FROM (VALUES (1, 'x'), (2, 'y')) AS t(a, b)").write_parquet(str(p))
    finally:
        con.close()
    return p


def test_load_parquet_and_query_roundtrip(tmp_path: Path, tiny_parquet: Path) -> None:
    store = Store(data_dir=tmp_path)
    try:
        store.load_parquet("tiny", tiny_parquet)
        rows = store.query("SELECT * FROM tiny ORDER BY a")
        assert rows == [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        assert store.tables() == ["tiny"]
    finally:
        store.close()


def test_load_parquet_invalid_name_raises(tmp_path: Path, tiny_parquet: Path) -> None:
    store = Store(data_dir=tmp_path)
    try:
        with pytest.raises(ValueError, match="invalid table name"):
            store.load_parquet("9bad-name", tiny_parquet)
        with pytest.raises(ValueError, match="invalid table name"):
            store.load_parquet("drop table users; --", tiny_parquet)
    finally:
        store.close()


def test_load_parquet_missing_file_raises(tmp_path: Path) -> None:
    store = Store(data_dir=tmp_path)
    try:
        with pytest.raises(FileNotFoundError):
            store.load_parquet("nope")
    finally:
        store.close()


def test_load_all_finds_every_parquet_in_dir(tmp_path: Path) -> None:
    con = duckdb.connect(":memory:")
    try:
        for name in ("zeta", "alpha", "mid"):
            con.sql("SELECT 1 AS x").write_parquet(str(tmp_path / f"{name}.parquet"))
    finally:
        con.close()

    store = Store(data_dir=tmp_path)
    try:
        loaded = store.load_all()
        assert set(loaded) == {"alpha", "mid", "zeta"}
        assert store.tables() == sorted(store.tables())
    finally:
        store.close()


def test_load_all_empty_dir_returns_empty(tmp_path: Path) -> None:
    store = Store(data_dir=tmp_path)
    try:
        assert store.load_all() == []
        assert store.tables() == []
    finally:
        store.close()


def test_load_all_nonexistent_dir_returns_empty(tmp_path: Path) -> None:
    store = Store(data_dir=tmp_path / "does-not-exist")
    try:
        assert store.load_all() == []
    finally:
        store.close()


def test_query_with_parameters(tmp_path: Path, tiny_parquet: Path) -> None:
    store = Store(data_dir=tmp_path)
    try:
        store.load_parquet("tiny", tiny_parquet)
        rows = store.query("SELECT b FROM tiny WHERE a = ?", [1])
        assert rows == [{"b": "x"}]
    finally:
        store.close()


def test_query_returns_empty_list_for_no_matches(tmp_path: Path, tiny_parquet: Path) -> None:
    store = Store(data_dir=tmp_path)
    try:
        store.load_parquet("tiny", tiny_parquet)
        assert store.query("SELECT * FROM tiny WHERE a = 999") == []
    finally:
        store.close()


def test_context_manager_closes_connection(tmp_path: Path, tiny_parquet: Path) -> None:
    with Store(data_dir=tmp_path) as s:
        s.load_parquet("tiny", tiny_parquet)
        assert s.tables() == ["tiny"]
    # After exit, the underlying duckdb connection is closed; further queries fail.
    with pytest.raises(Exception):  # noqa: B017 — duckdb raises ConnectionException, but the type isn't part of the public API contract.
        s.query("SELECT 1")
