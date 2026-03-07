"""
Input Classifier — determines input type and selects the first analyzer.

Uses the `file` system command + python-magic for file inputs.
Applies deterministic rules; falls back to AI if type is unknown.
"""

import subprocess
from pathlib import Path
from typing import Any

import magic  # python-magic

from app.classifier.rules import apply_rules


def classify(raw_input: str) -> tuple[str | None, str, str]:
    """
    Classify the input and return (analyzer_name | None, mime_type, magic_output).

    analyzer_name is None when no deterministic rule matched — caller must
    use the AI Decision Engine for fallback classification.
    """
    path = Path(raw_input)

    if path.exists() and path.is_file():
        try:
            mime_type: str = magic.from_file(str(path), mime=True)
        except Exception:
            mime_type = "application/octet-stream"
        try:
            magic_output: str = magic.from_file(str(path))
        except Exception:
            magic_output = ""
    else:
        # String input (URL / IP / domain) — no file to inspect
        mime_type = "text/plain"
        magic_output = raw_input

    analyzer = apply_rules(mime_type, magic_output, raw_input)
    return analyzer, mime_type, magic_output


def get_file_head(file_path: str, lines: int = 100) -> str:
    """Return the first N lines of a file (used in AI fallback context)."""
    try:
        result = subprocess.run(
            ["head", f"-{lines}", file_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout
    except Exception:
        return ""
