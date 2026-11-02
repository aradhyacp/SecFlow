#!/usr/bin/env python3
"""Replay deterministic scenarios through the legacy Python orchestrator.

This driver is invoked by the gated TypeScript parity test. It never calls a
real analyzer or an LLM: the classifier, routing decisions, analyzer callers,
and payload downloader are monkeypatched to the shared fixtures.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
import tempfile
import types
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
ORCHESTRATOR_ROOT = REPO_ROOT / "backend" / "orchestrator"
sys.path.insert(0, str(ORCHESTRATOR_ROOT))

# The host does not need libmagic for the replay; file scenarios supply their
# classifier verdict explicitly, and string scenarios never touch magic.
try:  # pragma: no cover - host dependent
    import magic  # noqa: F401
except ImportError:  # pragma: no cover - host dependent
    stub = types.ModuleType("magic")
    stub.from_file = lambda path, mime=False: (  # type: ignore[attr-defined]
        "application/octet-stream" if mime else "data"
    )
    sys.modules["magic"] = stub

from jsonschema import ValidationError, validate  # noqa: E402

from app import orchestrator as orch  # noqa: E402
from app.reporter.report_generator import SCHEMA_PATH, _build_base_report  # noqa: E402


def _scenario_input(scenario: dict[str, Any], work_dir: Path) -> tuple[str, Path | None]:
    spec = scenario["input"]
    if spec["kind"] == "target":
        return spec["value"], None

    suffix = f"_{spec['displayName']}"
    handle = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix,
        dir=work_dir,
        prefix="secflow-parity-",
    )
    if "bytesBase64" in spec:
        handle.write(base64.b64decode(spec["bytesBase64"]))
    elif "bytesHex" in spec:
        handle.write(bytes.fromhex(spec["bytesHex"]))
    else:
        handle.write(b"secflow parity sample")
    handle.close()
    return handle.name, Path(handle.name)


def _report_valid(report: dict[str, Any]) -> bool:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        validate(instance=report, schema=schema)
        return True
    except ValidationError:
        return False


def run_scenario(scenario: dict[str, Any], fixtures: dict[str, Any], root: Path) -> dict[str, Any]:
    work_dir = Path(tempfile.mkdtemp(prefix=f"secflow-parity-{scenario['name']}-", dir=root))
    user_input, file_path = _scenario_input(scenario, work_dir)
    results = fixtures["results"]
    decisions = list(scenario["decisions"])
    decision_index = 0
    decision_calls: list[dict[str, Any]] = []
    download_paths: list[Path] = []
    download_attempts: list[str] = []
    download_successes: list[str] = []

    original_classify = orch.classify
    original_decide = orch.decide_next
    original_callers = orch._CALLER_MAP
    original_download = orch._download_payload

    def fake_decide(
        result: dict[str, Any],
        pass_number: int,
        max_passes: int,
        tools_run: list[str],
    ) -> dict[str, Any]:
        nonlocal decision_index
        if decision_index >= len(decisions):
            raise RuntimeError(
                f"{scenario['name']}: Python requested more decisions than the fixture provides"
            )
        entry = decisions[decision_index]
        decision_index += 1
        action = entry["action"]
        next_tool = None if action == "finish" else action.removeprefix("analyze_")
        decision_calls.append(
            {
                "pass": pass_number,
                "action": entry["action"],
                "target": entry.get("target"),
            }
        )
        return {
            "next_tool": next_tool,
            "target": entry.get("target"),
            "reasoning": entry.get("reasoning", "deterministic parity decision"),
        }

    def make_caller(analyzer: str):
        def caller(input_value: str, pass_number: int) -> dict[str, Any]:
            if scenario.get("failAnalyzer") == analyzer:
                raise RuntimeError("synthetic analyzer failure")
            template = copy.deepcopy(results[analyzer])
            return {
                "analyzer": analyzer,
                "pass": pass_number,
                "input": input_value,
                **template,
            }

        return caller

    def fake_download(url: str) -> tuple[str, str]:
        download_attempts.append(url)
        download = scenario.get("download")
        if not download or url != download["url"]:
            raise RuntimeError(f"{scenario['name']}: unexpected payload URL {url!r}")
        download_successes.append(url)
        handle = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=download["extension"],
            dir=work_dir,
            prefix="payload-",
        )
        handle.write(b"MZ synthetic downloaded payload")
        handle.close()
        download_paths.append(Path(handle.name))
        return handle.name, download["contentType"]

    try:
        if scenario.get("firstAnalyzer"):
            analyzer = scenario["firstAnalyzer"]
            mime = scenario.get("mimeType", "application/octet-stream")
            magic_output = scenario.get("magicOutput", "data")
            orch.classify = lambda _raw: (analyzer, mime, magic_output)
        else:
            orch.classify = original_classify

        orch.decide_next = fake_decide
        orch._CALLER_MAP = {name: make_caller(name) for name in results}
        orch._download_payload = fake_download

        store = orch.run_pipeline(user_input, max_passes=3)
        findings = store.get_all()
        report = _build_base_report(findings)
        overall_risk = max(
            (float(item.get("risk_score", 0.0)) for item in findings),
            default=0.0,
        )
    finally:
        orch.classify = original_classify
        orch.decide_next = original_decide
        orch._CALLER_MAP = original_callers
        orch._download_payload = original_download

    result = {
        "name": scenario["name"],
        "input": user_input,
        "displayName": scenario["input"].get("displayName") or scenario["input"]["value"],
        "inputKind": scenario["input"]["kind"],
        "jobId": hashlib.sha256(user_input.encode()).hexdigest()[:16],
        "analyzers": [item.get("analyzer") for item in findings],
        "totalPasses": len(findings),
        "overallRiskScore": round(overall_risk, 2),
        "findings": findings,
        "report": report,
        "reportValid": _report_valid(report),
        "decisions": decision_calls,
        "downloadAttempts": download_attempts,
        "downloadSuccesses": download_successes,
        "downloadsCleaned": all(not path.exists() for path in download_paths),
    }

    # The parity harness owns the synthetic upload; remove it after recording
    # the pipeline output (the Flask route does the same for real uploads).
    shutil.rmtree(work_dir, ignore_errors=True)
    return result


def api_probe(fixtures: dict[str, Any], root: Path) -> dict[str, Any]:
    """Exercise the legacy Flask route with fixed findings and a report stub."""
    import app.routes as routes  # noqa: PLC0415
    from app import create_app  # noqa: PLC0415
    from app.store.findings_store import FindingsStore  # noqa: PLC0415

    results = fixtures["results"]
    findings = [
        {
            "analyzer": "recon",
            "pass": 1,
            "input": "8.8.8.8",
            **copy.deepcopy(results["recon"]),
        },
        {
            "analyzer": "web",
            "pass": 2,
            "input": "https://start.example",
            **copy.deepcopy(results["web"]),
        },
    ]
    store = FindingsStore()
    for entry in findings:
        store.append(entry)

    original_run = routes.run_pipeline
    original_generate = routes.generate_report

    def fake_run_pipeline(_user_input: str, max_passes: int = 3) -> FindingsStore:
        return store

    def fake_generate_report(
        findings_json: str,
        job_id: str,
        output_dir: str = "/app/reports",
        base_name: str = "report",
    ) -> dict[str, str]:
        # The legacy route hardcodes /app/reports; parity writes to the temp
        # root instead of trying to create a host root directory.
        target = root / "api-report"
        target.mkdir(parents=True, exist_ok=True)
        json_path = target / f"{base_name}.json"
        html_path = target / f"{base_name}.html"
        json_path.write_text(findings_json, encoding="utf-8")
        html_path.write_text("<html>parity</html>", encoding="utf-8")
        return {"json": str(json_path), "html": str(html_path)}

    try:
        routes.run_pipeline = fake_run_pipeline
        routes.generate_report = fake_generate_report
        app = create_app()
        app.config.update(TESTING=True)
        client = app.test_client()
        health = client.get("/api/health")
        response = client.post(
            "/api/smart-analyze?passes=3",
            json={"target": "8.8.8.8"},
        )
        body = response.get_json()
        body["report_paths"] = {
            key: Path(value).name for key, value in body.get("report_paths", {}).items()
        }
        return {
            "healthStatus": health.status_code,
            "healthBody": health.get_json(),
            "analyzeStatus": response.status_code,
            "analyzeBody": body,
        }
    finally:
        routes.run_pipeline = original_run
        routes.generate_report = original_generate


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: python_driver.py <fixtures.json> <output.json>", file=sys.stderr)
        return 2
    fixture_path = Path(sys.argv[1]).resolve()
    output_path = Path(sys.argv[2]).resolve()
    fixtures = json.loads(fixture_path.read_text(encoding="utf-8"))

    root = Path(tempfile.mkdtemp(prefix="secflow-parity-run-"))
    try:
        output = {
            "pythonVersion": sys.version,
            "scenarios": [
                run_scenario(scenario, fixtures, root) for scenario in fixtures["scenarios"]
            ],
            "api": api_probe(fixtures, root),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)

    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
