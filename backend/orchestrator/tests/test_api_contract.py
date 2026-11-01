"""Baseline tests for the frontend-facing HTTP contract (Step 1).

The frontend (frontend/src/config/api.js + SmartPipelinePage.jsx) only depends on:

    GET  /api/health
    POST /api/smart-analyze?passes=N   → job_id, passes_completed,
                                          overall_risk_score, findings_summary,
                                          report_urls{json,html}
    GET  /api/report/<job_id>/json|html

run_pipeline / generate_report are stubbed so the tests never call analyzers or
an LLM.
"""

from __future__ import annotations

import re

import pytest

from conftest import load_fixture

from app import create_app
from app.store.findings_store import FindingsStore


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    app = create_app()
    app.config.update(TESTING=True)

    fixture = load_fixture("smart-analyze-response.json")

    def fake_run_pipeline(user_input: str, max_passes: int = 3) -> FindingsStore:
        store = FindingsStore()
        for entry in fixture["findings_summary"]:
            store.append(entry)
        return store

    def fake_generate_report(findings_json: str, job_id: str, output_dir: str, base_name: str):
        return {"json": f"{output_dir}/{base_name}.json", "html": f"{output_dir}/{base_name}.html"}

    monkeypatch.setattr("app.routes.run_pipeline", fake_run_pipeline)
    monkeypatch.setattr("app.routes.generate_report", fake_generate_report)
    return app.test_client()


def test_health(client) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "healthy", "service": "secflow-orchestrator"}


def test_smart_analyze_json_target(client) -> None:
    response = client.post("/api/smart-analyze?passes=3", json={"target": "recongraph.xyz"})
    assert response.status_code == 200

    payload = response.get_json()
    assert set(payload) == {
        "job_id",
        "passes_completed",
        "overall_risk_score",
        "findings_summary",
        "report_paths",
        "report_urls",
    }
    assert re.fullmatch(r"[0-9a-f]{16}", payload["job_id"])
    assert payload["passes_completed"] == 3
    assert payload["overall_risk_score"] == 9.5
    assert [p["analyzer"] for p in payload["findings_summary"]] == ["macro", "recon", "web"]
    assert payload["report_urls"] == {
        "json": f"/api/report/{payload['job_id']}/json",
        "html": f"/api/report/{payload['job_id']}/html",
    }


@pytest.mark.parametrize("passes", ["1", "2", "6"])
def test_smart_analyze_rejects_out_of_range_pass_count(client, passes: str) -> None:
    response = client.post(f"/api/smart-analyze?passes={passes}", json={"target": "8.8.8.8"})
    assert response.status_code == 400
    assert "passes must be 3, 4, or 5" in response.get_json()["error"]


def test_smart_analyze_non_numeric_passes_defaults_to_three(client) -> None:
    # Baseline behaviour: int() failure silently falls back to 3 rather than 400.
    response = client.post("/api/smart-analyze?passes=abc", json={"target": "8.8.8.8"})
    assert response.status_code == 200


def test_smart_analyze_requires_input(client) -> None:
    response = client.post("/api/smart-analyze", json={})
    assert response.status_code == 400
    assert "target" in response.get_json()["error"]


def test_smart_analyze_rejects_other_content_types(client) -> None:
    response = client.post("/api/smart-analyze", data="raw", content_type="text/plain")
    assert response.status_code == 400


def test_report_rejects_unknown_format(client) -> None:
    response = client.get("/api/report/9f2c4a1b7d3e5f60/pdf")
    assert response.status_code == 400


def test_report_rejects_non_hex_job_id(client) -> None:
    response = client.get("/api/report/../../etc/passwd/html")
    assert response.status_code in (400, 404)


def test_report_missing_returns_404(client) -> None:
    response = client.get("/api/report/deadbeefdeadbeef/json")
    assert response.status_code == 404
