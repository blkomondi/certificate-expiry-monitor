"""Environment variable and .env file support."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


def load_dotenv(env_file: str | Path = ".env") -> None:
    """Load environment variables from .env file."""
    env_path = Path(env_file)
    if not env_path.exists():
        return

    with open(env_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if key not in os.environ:
                os.environ[key] = value


def env_substitute(value: str) -> str:
    """Substitute ${VAR_NAME} patterns with environment variables."""
    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))
    return re.sub(r'\$\{(\w+)\}', _replace, value)


def env_substitute_config(obj: Any) -> Any:
    """Recursively substitute environment variables in config."""
    if isinstance(obj, str):
        return env_substitute(obj)
    if isinstance(obj, dict):
        return {k: env_substitute_config(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [env_substitute_config(item) for item in obj]
    return obj