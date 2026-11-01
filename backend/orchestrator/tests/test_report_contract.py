"""Baseline tests for the report contract (Step 1).

Verifies that the report builder turns raw findings into the PWNDoc-compatible
shape documented in app/reporter/pwndoc_schema.json — without calling any LLM.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import validate

from conftest import load_fixture

from app.reporter.report_generator import SCHEMA_PATH, _build_base_report


def test_base_report_matches_pwndoc_schema() -> None:
    response = load_fixture("smart-analyze-response.json")
    report = _build_base_report(response["findings_summary"])

    schema = json.loads(SCHEMA_PATH.read_text())
    validate(instance=report, schema=schema)

    assert report["input"] == "/tmp/tmpXXXX_invoice.docm"
    assert report["total_passes"] == 3
    assert report["overall_risk_score"] == 9.5
    assert [p["analyzer"] for p in report["passes"]] == ["macro", "recon", "web"]
    assert [p["pass_number"] for p in report["passes"]] == [1, 2, 3]
    assert report["summary"] == "Automated analysis completed."
    assert report["recommendations"] == []


def test_sample_report_fixture_is_schema_valid() -> None:
    report = load_fixture("report.json")
    report.pop("_note", None)

    schema = json.loads(SCHEMA_PATH.read_text())
    validate(instance=report, schema=schema)


def test_schema_path_exists() -> None:
    assert isinstance(SCHEMA_PATH, Path)
    assert SCHEMA_PATH.name == "pwndoc_schema.json"
    assert SCHEMA_PATH.exists()
