"""
core/config.py - Minimal environment configuration loader for CONFIGRA.

Loads a local ``.env`` file (if present) without adding a dependency and
exposes the API authentication key used by the web layer.

Existing process environment variables always take precedence over ``.env``
values. Secrets are never logged or rendered outside the intended auth flow.
"""

from __future__ import annotations

import os
from typing import Optional

_LOADED = False


def load_dotenv(path: str = ".env") -> None:
    """Load simple ``KEY=VALUE`` pairs from ``path`` into ``os.environ``.

    Idempotent and intentionally small: comments (``#``), blank lines, and
    values with optional matching single/double quotes are supported.
    Existing environment variables are not overwritten.
    """
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if not key:
                    continue
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                if key not in os.environ:
                    os.environ[key] = value
    except OSError:
        return


def get_api_key() -> str:
    """Return the configured CONFIGRA API key (empty string when unset)."""
    load_dotenv()
    return (os.environ.get("CONFIGRA_API_KEY") or "").strip()


def get_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Return an environment value after ensuring ``.env`` has been loaded."""
    load_dotenv()
    value = os.environ.get(name)
    return default if value is None else value
