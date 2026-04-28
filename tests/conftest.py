"""Shared pytest fixtures for the cdp test suite.

Design goals:

- Tests must never write to the repo's real ``data/`` directory.
- The synthetic dataset is deterministic, so we generate it once per session
  and copy it into per-test tmp dirs (cheap shutil.copy2 instead of regenerate).
- ``CDP_DATA_DIR`` and ``ANTHROPIC_API_KEY`` are scrubbed/redirected per test
  so any code path that calls ``Settings.load()`` is hermetic.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from cdp.ingest import generate_synthetic_dataset
from cdp.store import Store

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "detections"


@pytest.fixture
def tmp_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Per-test tmp data dir; ``CDP_DATA_DIR`` is repointed at it."""
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("CDP_DATA_DIR", str(d))
    # Never let a real key leak into a test run.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return d


@pytest.fixture(scope="session")
def synthetic_dataset_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Generate the deterministic synthetic dataset once per session."""
    d = tmp_path_factory.mktemp("synthetic-data")
    generate_synthetic_dataset(d)
    return d


@pytest.fixture
def seeded_data_dir(tmp_data_dir: Path, synthetic_dataset_dir: Path) -> Path:
    """Per-test data dir pre-populated by copying the cached synthetic Parquet files."""
    for parquet in synthetic_dataset_dir.glob("*.parquet"):
        shutil.copy2(parquet, tmp_data_dir / parquet.name)
    return tmp_data_dir


@pytest.fixture
def seeded_store(seeded_data_dir: Path) -> Iterator[Store]:
    """Per-test :class:`Store` loaded with the synthetic dataset."""
    store = Store(data_dir=seeded_data_dir)
    store.load_all()
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def detections_dir() -> Path:
    """Absolute path to the repo's ``detections/`` directory."""
    return DETECTIONS_DIR
