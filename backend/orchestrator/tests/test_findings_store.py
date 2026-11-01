"""Baseline tests for the findings store (Step 1)."""

from __future__ import annotations

import json

from app.store.findings_store import FindingsStore


def _entry(analyzer: str, pass_number: int, risk: float) -> dict:
    return {
        "analyzer": analyzer,
        "pass": pass_number,
        "input": f"target-{pass_number}",
        "findings": [{"type": "x", "detail": "d", "severity": "info", "evidence": ""}],
        "risk_score": risk,
        "raw_output": "",
    }


def test_append_preserves_pass_order_and_identity() -> None:
    store = FindingsStore()
    store.append(_entry("macro", 1, 9.5))
    store.append(_entry("recon", 2, 4.0))

    all_findings = store.get_all()
    assert [p["analyzer"] for p in all_findings] == ["macro", "recon"]
    assert [p["pass"] for p in all_findings] == [1, 2]
    assert store.last()["analyzer"] == "recon"
    assert store.is_empty() is False


def test_to_json_round_trips() -> None:
    store = FindingsStore()
    store.append(_entry("web", 1, 2.5))

    payload = json.loads(store.to_json())
    assert payload == store.get_all()


def test_empty_store() -> None:
    store = FindingsStore()
    assert store.is_empty() is True
    assert store.last() is None
    assert json.loads(store.to_json()) == []
