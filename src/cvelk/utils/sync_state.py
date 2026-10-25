"""Persistent checkpoints for incremental syncs."""

import json
from pathlib import Path
from typing import Any

from loguru import logger


class SyncState:
    """A small JSON key/value file recording what the last successful sync applied.

    Keys include the CVE List V5 commit and the EPSS/KEV feed versions
    already written to Elasticsearch.
    """

    def __init__(self, path: Path):
        """Initialize sync state.

        Args:
            path: JSON file holding the state.
        """
        self.path = path

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, key: str) -> str | None:
        """Return a stored value, or None if it is missing or not a string."""
        value = self._load().get(key)
        return value if isinstance(value, str) else None

    def set(self, key: str, value: str) -> bool:
        """Store a value, keeping the other keys.

        Returns:
            True if the state file was written.
        """
        data = self._load()
        data[key] = value
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, sort_keys=True) + "\n")
        except OSError as e:
            logger.warning(f"Unable to save sync state: {e}")
            return False
        return True
