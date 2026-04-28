"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

DEFAULT_MODEL = "claude-sonnet-4-5"
DEFAULT_DATA_DIR = Path("./data")


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the platform."""

    data_dir: Path
    anthropic_api_key: str | None
    model: str

    @classmethod
    def load(cls) -> Settings:
        # Load a .env file from CWD or any parent directory if one exists.
        # Idempotent: existing process env vars take precedence over file values.
        load_dotenv(find_dotenv(usecwd=True))
        raw_dir = os.getenv("CDP_DATA_DIR", str(DEFAULT_DATA_DIR))
        return cls(
            data_dir=Path(raw_dir).expanduser().resolve(),
            # Treat empty string as missing (annoying real-world edge case).
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY") or None,
            model=os.getenv("CDP_MODEL", DEFAULT_MODEL),
        )

    @property
    def has_anthropic_key(self) -> bool:
        return bool(self.anthropic_api_key)
