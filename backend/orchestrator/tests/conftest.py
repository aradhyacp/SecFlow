"""Shared test setup for the baseline (pre-migration) orchestrator contract tests.

The tests target the *externally visible* behaviour of the Python orchestrator:
deterministic classifier rules, analyzer adapters, the findings store, the
report shape and the HTTP routes. They must keep passing until the Python
orchestrator is removed in Step 11 of the migration spec.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

ORCHESTRATOR_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).resolve().parents[3] / "docs" / "ts-migration" / "fixtures"

sys.path.insert(0, str(ORCHESTRATOR_ROOT))

# python-magic needs libmagic at runtime. Contract tests do not exercise real
# MIME sniffing (that needs the Docker image), so fall back to a deterministic
# stub when libmagic is unavailable on the host.
try:  # pragma: no cover - depends on host
    import magic  # noqa: F401
except ImportError:  # pragma: no cover - depends on host
    _stub = types.ModuleType("magic")
    _stub.from_file = lambda path, mime=False: (  # type: ignore[attr-defined]
        "application/octet-stream" if mime else "data"
    )
    sys.modules["magic"] = _stub


def load_fixture(name: str) -> Any:
    """Load a JSON fixture from docs/ts-migration/fixtures."""
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture()
def fixture() -> Any:
    return load_fixture


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES_DIR
