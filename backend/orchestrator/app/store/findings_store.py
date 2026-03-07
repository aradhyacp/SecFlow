"""
Findings Store — append-only, thread-safe accumulator for all analyzer outputs.
"""

import json
import threading
from typing import Any


class FindingsStore:
    """Accumulates normalized analyzer outputs across all loop passes."""

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def append(self, finding: dict[str, Any]) -> None:
        """Append a normalized finding dict (SecFlow contract shape)."""
        with self._lock:
            self._findings.append(finding)

    def get_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._findings)

    def to_json(self) -> str:
        return json.dumps(self.get_all(), indent=2)

    def is_empty(self) -> bool:
        with self._lock:
            return len(self._findings) == 0

    def last(self) -> dict[str, Any] | None:
        findings = self.get_all()
        return findings[-1] if findings else None

    def save_to_disk(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
