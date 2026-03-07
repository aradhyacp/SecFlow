# SecFlow — Integration Guide

Setting up the analyzer microservices alongside the new SecFlow pipeline.

---

## Table of Contents

1. [Integration Strategy](#1-integration-strategy)
2. [Architecture Decision — Why Keep Microservices](#2-architecture-decision--why-keep-microservices)
3. [New Project Structure](#3-new-project-structure)
4. [What Changes vs What Stays the Same](#4-what-changes-vs-what-stays-the-same)
5. [Step-by-Step Setup Tasks](#5-step-by-step-setup-tasks)
6. [The Orchestrator Service (New)](#6-the-orchestrator-service-new)
7. [The Adapter Pattern](#7-the-adapter-pattern)
8. [Updated compose.yml](#8-updated-composeyml)
9. [API Contracts — All Endpoints](#9-api-contracts--all-endpoints)
10. [URL Analyzer — What To Do With It](#10-url-analyzer--what-to-do-with-it)
11. [Environment Variables](#11-environment-variables)
12. [Testing Checklist](#12-testing-checklist)

---

## 1. Integration Strategy

SecFlow uses **5 independent analyzer microservices**, each running in its own Docker container. The integration approach is:

> **Keep the analyzers exactly as they are. Add one new Docker service — the Orchestrator — that calls them via HTTP.**

The Orchestrator service is the only net-new code. It:
- Exposes `POST /api/smart-analyze`  
- Runs the AI loop, calling existing analyzer APIs over the Docker internal network
- Uses **adapter functions** to translate each analyzer's existing response format into the standard SecFlow findings contract
- Collects all findings in the Findings Store
- Generates the PWNDoc report at the end

This approach means zero rework of any existing analyzer code. The adapters absorb any format differences.

---

## 2. Architecture Decision — Why Keep Microservices

| Approach | Pros | Cons |
|---|---|---|
| **Keep microservices + add orchestrator (chosen)** | Zero rework of existing code; each analyzer independently deployable and scalable; Docker isolation preserved; can upgrade analyzers without touching orchestrator | Orchestrator communicates over network (small latency overhead) |
| Merge everything into a monolith | Single codebase; no network overhead | Rewrites all 5 analyzers; loses Docker isolation; harder to upgrade individual analyzers |
| Keep microservices but rewrite orchestrator to import modules | Direct function calls | Requires each analyzer to be importable as a Python package — breaks Docker self-containment |

**Chosen: Option 1.** The orchestrator speaks to analyzers over Docker's internal network using service names (`http://malware-analyzer:5001/...`). This is transparent to any code outside Docker Compose.

---

## 3. New Project Structure

```
backend/
│
├── orchestrator/                        ← NEW Docker service (port 5000)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes.py                    ← Flask: POST /api/smart-analyze
│   │   ├── orchestrator.py              ← Pipeline loop logic
│   │   ├── classifier/
│   │   │   ├── classifier.py            ← Input type detection
│   │   │   └── rules.py                 ← Deterministic routing rules
│   │   ├── ai/
│   │   │   ├── engine.py                ← Gemini tool-calling wrapper
│   │   │   └── keywords.txt             ← Grep fallback keyword list
│   │   ├── adapters/                    ← Response format translators
│   │   │   ├── malware_adapter.py
│   │   │   ├── steg_adapter.py
│   │   │   ├── recon_adapter.py
│   │   │   ├── url_adapter.py
│   │   │   └── web_adapter.py
│   │   ├── store/
│   │   │   └── findings_store.py        ← Append-only findings accumulator
│   │   └── reporter/
│   │       ├── report_generator.py      ← Gemini → JSON/PDF/HTML report
│   │       └── pwndoc_schema.json       ← PWNDoc output schema
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
│
├── malware-analyzer/                    ← Analyzer microservice
├── steg-analyzer/                       ← Analyzer microservice
├── recon-analyzer/                      ← Analyzer microservice
├── url-analyzer/                        ← Analyzer microservice (internal only)
├── web-analyzer/                        ← Analyzer microservice
│
├── compose.yml                          ← UPDATED: adds orchestrator service
├── .env.example                         ← UPDATED: adds GEMINI_API_KEY
└── readme.md
```

### Service Ports

| Service | Port | Exposed Route |
|---|---|---|
| Orchestrator (new) | 5000 | `POST /api/smart-analyze` |
| Malware Analyzer | 5001 | `POST /api/malware-analyzer/` |
| Steg Analyzer | 5002 | `POST /api/steg-analyzer/` |
| Recon Analyzer | 5003 | `POST /api/recon-analyzer/` |
| URL Analyzer | 5004 | Internal only (called by orchestrator) |
| Web Analyzer | 5005 | `POST /api/web-analyzer/` |

---

## 4. What Changes vs What Stays the Same

### Stays the Same
- All 5 analyzer service directories — no code changes required
- Each analyzer's `Dockerfile`
- Each analyzer's `requirements.txt`
- Each analyzer's internal logic and API routes
- The Docker Compose service definitions for existing 5 analyzers

### Changes (Updated)
- `compose.yml` — add orchestrator service + shared network
- Root `.env.example` — add `GEMINI_API_KEY` and other new vars

### New (Added)
- `backend/orchestrator/` — entire new Docker service directory
- All adapters, AI engine, findings store, report generator live here

---

## 5. Step-by-Step Setup Tasks

### Task 1 — Verify Analyzer Directory Structure

Ensure all analyzer directories are present under `backend/` with lowercase kebab-case names:

```
backend/malware-analyzer/
backend/recon-analyzer/
backend/steg-analyzer/
backend/url-analyzer/
backend/web-analyzer/
```

### Task 2 — Verify All Services Start

```bash
cd backend
docker compose up malware-analyzer steg-analyzer recon-analyzer url-analyzer web-analyzer
```

Test each one independently:
```bash
# Malware
curl -X POST http://localhost:5001/api/malware-analyzer/ \
  -F "file=@/path/to/test.exe"

# Steg
curl -X POST http://localhost:5002/api/steg-analyzer/ \
  -F "file=@/path/to/test.png"

# Recon
curl -X POST http://localhost:5003/api/recon-analyzer/ \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# Web
curl -X POST http://localhost:5005/api/web-analyzer/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Document each service's exact request/response format — you will need this for writing adapters.

### Task 3 — Understand Each Analyzer's Response Format

Before writing adapters, map out exactly what each analyzer returns. For example, if the malware analyzer returns:
```json
{
  "status": "success",
  "hashes": { "md5": "...", "sha256": "..." },
  "yara_matches": ["Trojan.GenericKDZ"],
  "strings": ["http://evil.com/beacon"],
  "risk_level": "HIGH"
}
```

You will write an adapter that converts this into:
```json
{
  "analyzer": "malware",
  "pass": 1,
  "input": "sample.exe",
  "findings": [
    { "type": "signature_match", "detail": "Trojan.GenericKDZ", "severity": "critical", "evidence": "YARA match" },
    { "type": "suspicious_string", "detail": "http://evil.com/beacon", "severity": "high", "evidence": "http://evil.com/beacon" }
  ],
  "risk_score": 8.5,
  "raw_output": "hashes: {...}, yara: [...], strings: [...]"
}
```

### Task 4 — Scaffold the Orchestrator Service

```bash
mkdir -p backend/orchestrator/app/{classifier,ai,adapters,store,reporter}
touch backend/orchestrator/app/__init__.py
touch backend/orchestrator/app/routes.py
touch backend/orchestrator/app/orchestrator.py
touch backend/orchestrator/app/classifier/{classifier.py,rules.py}
touch backend/orchestrator/app/ai/{engine.py,keywords.txt}
touch backend/orchestrator/app/adapters/{malware_adapter.py,steg_adapter.py,recon_adapter.py,url_adapter.py,web_adapter.py}
touch backend/orchestrator/app/store/findings_store.py
touch backend/orchestrator/app/reporter/{report_generator.py,pwndoc_schema.json}
touch backend/orchestrator/{Dockerfile,requirements.txt,.env.example}
```

### Task 5 — Write Adapters

Write one adapter per analyzer (see [Section 7](#7-the-adapter-pattern)).

### Task 6 — Build the Orchestrator Core

Implement in this order (each is independently testable):
1. `findings_store.py`
2. `classifier.py` + `rules.py`
3. `ai/engine.py`
4. All adapters
5. `orchestrator.py` (the loop)
6. `reporter/report_generator.py`
7. `routes.py` (Flask wrapper)

### Task 7 — Write the Orchestrator Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# System deps for file classification
RUN apt-get update && apt-get install -y \
    libmagic1 file \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

ENV FLASK_APP=app.routes
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
```

### Task 8 — Update compose.yml

Add the orchestrator service and a shared Docker network (see [Section 8](#8-updated-composeyml)).

### Task 9 — Integration Test

Bring up all services and run an end-to-end test:
```bash
docker compose up --build
python test_e2e.py --input suspicious.png --passes 3
```

---

## 6. The Orchestrator Service (New)

### `app/routes.py` — Flask API

```python
# backend/orchestrator/app/routes.py
import os
import uuid
import tempfile
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

from app.orchestrator import run_pipeline
from app.reporter.report_generator import generate_report

app = Flask(__name__)


@app.route("/api/smart-analyze", methods=["POST"])
def smart_analyze():
    """
    Accepts:
      - multipart/form-data with 'file' field, OR
      - application/json with {"target": "<url|ip|domain>"}

    Query params:
      - passes: int (3, 4, or 5) — default 3
    """
    passes = int(request.args.get("passes", 3))
    if passes not in (3, 4, 5):
        return jsonify({"error": "passes must be 3, 4, or 5"}), 400

    # Handle file upload
    if "file" in request.files:
        uploaded = request.files["file"]
        tmp = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=f"_{uploaded.filename}"
        )
        uploaded.save(tmp.name)
        user_input = tmp.name

    # Handle string target (URL / IP / domain)
    elif request.is_json and "target" in request.json:
        user_input = request.json["target"]
    else:
        return jsonify({"error": "Provide 'file' (multipart) or 'target' (JSON)"}), 400

    try:
        store = run_pipeline(user_input, max_passes=passes)

        if store.is_empty():
            return jsonify({"error": "No findings collected"}), 500

        job_id = str(uuid.uuid4())[:8]
        output_dir = f"/tmp/secflow_reports/{job_id}"

        paths = generate_report(
            findings_json=store.to_json(),
            output_dir=output_dir,
            base_name="report",
        )

        return jsonify({
            "job_id": job_id,
            "passes_completed": len(store.get_all()),
            "overall_risk_score": max(
                p.get("risk_score", 0) for p in store.get_all()
            ),
            "findings_summary": store.get_all(),
            "report_paths": paths,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
```

### `app/orchestrator.py` — The Loop (HTTP Version)

```python
# backend/orchestrator/app/orchestrator.py
import os
import re
import logging
import requests
from typing import Any

from app.classifier.classifier import classify, get_file_head
from app.ai.engine import decide_next
from app.store.findings_store import FindingsStore
from app.adapters import (
    malware_adapter, steg_adapter,
    recon_adapter, url_adapter, web_adapter,
)

log = logging.getLogger("secflow.orchestrator")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Docker-internal service URLs (resolved via Docker Compose service names)
ANALYZER_URLS = {
    "malware": os.getenv("MALWARE_ANALYZER_URL", "http://malware-analyzer:5001/api/malware-analyzer/"),
    "steg":    os.getenv("STEG_ANALYZER_URL",    "http://steg-analyzer:5002/api/steg-analyzer/"),
    "recon":   os.getenv("RECON_ANALYZER_URL",   "http://recon-analyzer:5003/api/recon-analyzer/"),
    "url":     os.getenv("URL_ANALYZER_URL",     "http://url-analyzer:5004/api/url-analyzer/"),
    "web":     os.getenv("WEB_ANALYZER_URL",     "http://web-analyzer:5005/api/web-analyzer/"),
}

ADAPTERS = {
    "malware": malware_adapter.adapt,
    "steg":    steg_adapter.adapt,
    "recon":   recon_adapter.adapt,
    "url":     url_adapter.adapt,
    "web":     web_adapter.adapt,
}


def _call_analyzer(tool: str, input_data: str, pass_number: int) -> dict[str, Any]:
    """
    Call the analyzer HTTP service, then run the adapter to produce
    a SecFlow-contract-compliant dict.
    """
    url = ANALYZER_URLS[tool]
    adapter_fn = ADAPTERS[tool]

    try:
        # File-based analyzers (malware, steg) need multipart upload
        if tool in ("malware", "steg"):
            with open(input_data, "rb") as f:
                resp = requests.post(url, files={"file": f}, timeout=120)
        else:
            # String-based analyzers (recon, url, web) send JSON
            payload_key = "url" if tool in ("web", "url") else "target"
            resp = requests.post(
                url,
                json={payload_key: input_data},
                timeout=60
            )
        resp.raise_for_status()
        raw_response = resp.json()

    except requests.exceptions.RequestException as e:
        log.error(f"Analyzer service call failed ({tool}): {e}")
        return {
            "analyzer": tool, "pass": pass_number, "input": input_data,
            "findings": [{"type": "error", "detail": str(e), "severity": "low", "evidence": ""}],
            "risk_score": 0.0, "raw_output": str(e),
        }

    # Transform old response format → SecFlow contract
    return adapter_fn(raw_response, pass_number, input_data)


def _extract_next_input(last_finding: dict[str, Any], next_tool: str) -> str | None:
    raw = last_finding.get("raw_output", "")
    findings = last_finding.get("findings", [])

    if next_tool in ("malware", "steg"):
        for f in findings:
            if f.get("extracted_path"):
                return f["extracted_path"]
        extracted = last_finding.get("extracted_files", [])
        if extracted:
            return extracted[0]

    if next_tool == "web":
        urls = re.findall(r'https?://[^\s"\'<>]+', raw)
        if urls:
            return urls[0]

    if next_tool == "recon":
        ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', raw)
        if ips:
            return ips[0]
        domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', raw)
        if domains:
            return domains[0]

    return last_finding.get("input")


def run_pipeline(user_input: str, max_passes: int = 3) -> FindingsStore:
    store = FindingsStore()

    # Pass 1 — deterministic classification (no AI)
    log.info(f"Pass 1 — classifying: {user_input}")
    first_analyzer, mime, magic_out = classify(user_input)

    if first_analyzer is None:
        log.info("Unknown type — asking AI for first analyzer")
        file_head = get_file_head(user_input)
        synthetic = {
            "analyzer": "classifier", "pass": 0, "input": user_input,
            "findings": [], "risk_score": 0.0,
            "raw_output": f"MIME: {mime}\nmagic: {magic_out}\nhead:\n{file_head}",
        }
        decision = decide_next(synthetic, pass_number=0, max_passes=max_passes)
        first_analyzer = decision["next_tool"]
        log.info(f"AI chose: {first_analyzer} — {decision['reasoning']}")

    if not first_analyzer:
        log.warning("Could not determine first analyzer. Aborting.")
        return store

    current_tool = first_analyzer
    current_input = user_input

    for pass_num in range(1, max_passes + 1):
        log.info(f"Pass {pass_num} — {current_tool} on {current_input}")
        result = _call_analyzer(current_tool, current_input, pass_num)
        store.append(result)
        log.info(f"Pass {pass_num} done — {len(result['findings'])} findings, risk={result['risk_score']}")

        if pass_num >= max_passes:
            log.info("Max passes reached.")
            break

        decision = decide_next(result, pass_number=pass_num, max_passes=max_passes)
        log.info(f"AI: next={decision['next_tool']} — {decision['reasoning']}")

        if not decision["next_tool"]:
            log.info("AI signalled termination.")
            break

        next_input = _extract_next_input(result, decision["next_tool"])
        if not next_input:
            log.warning("No extractable input for next analyzer. Stopping.")
            break

        current_tool = decision["next_tool"]
        current_input = next_input

    return store
```

---

## 7. The Adapter Pattern

Each adapter lives in `app/adapters/<name>_adapter.py`. Its job is to take whatever the old analyzer returned and produce a **SecFlow contract dict**.

### Adapter Interface (same for all)

```python
def adapt(raw_response: dict, pass_number: int, input_data: str) -> dict:
    """
    Args:
        raw_response:  The JSON response body from the analyzer HTTP service
        pass_number:   Current loop pass (1-indexed)
        input_data:    What was sent to the analyzer

    Returns:
        SecFlow contract dict:
        {
            "analyzer": str,
            "pass": int,
            "input": str,
            "findings": list[dict],
            "risk_score": float,      # 0.0 – 10.0
            "raw_output": str,
            "extracted_files": list[str]  # steg only
        }
    """
```

### Example: `malware_adapter.py`

> Adjust field names to match whatever your malware analyzer actually returns.

```python
# backend/orchestrator/app/adapters/malware_adapter.py
import json

SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high",
    "MEDIUM": "medium",     "LOW": "low",
    "INFO": "info",         "NONE": "info",
}

RISK_MAP = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}


def adapt(raw: dict, pass_number: int, input_data: str) -> dict:
    findings = []

    # --- Map hashes ---
    hashes = raw.get("hashes") or raw.get("file_hashes") or {}
    if hashes:
        findings.append({
            "type": "hash",
            "detail": f"MD5: {hashes.get('md5','?')}  SHA256: {hashes.get('sha256','?')}",
            "severity": "info",
            "evidence": json.dumps(hashes),
        })

    # --- Map YARA matches ---
    for match in raw.get("yara_matches") or raw.get("signatures") or []:
        findings.append({
            "type": "signature_match",
            "detail": f"YARA / signature match: {match}",
            "severity": "critical",
            "evidence": str(match),
        })

    # --- Map suspicious strings ---
    for s in (raw.get("suspicious_strings") or raw.get("strings") or [])[:20]:
        findings.append({
            "type": "suspicious_string",
            "detail": f"Flagged string: {s}",
            "severity": "high",
            "evidence": str(s),
        })

    # --- Map risk level ---
    raw_risk = str(raw.get("risk_level") or raw.get("severity") or "LOW").upper()
    sev = SEVERITY_MAP.get(raw_risk, "low")
    risk_score = min(10.0, sum(RISK_MAP.get(f["severity"], 0) for f in findings))

    return {
        "analyzer": "malware",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": json.dumps(raw),
    }
```

### Example: `steg_adapter.py`

```python
# backend/orchestrator/app/adapters/steg_adapter.py
import json

RISK_MAP = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}


def adapt(raw: dict, pass_number: int, input_data: str) -> dict:
    findings = []
    extracted_files = []

    # Embedded/extracted files
    for item in raw.get("extracted_files") or raw.get("embedded") or []:
        path = item if isinstance(item, str) else item.get("path", "")
        findings.append({
            "type": "embedded_file",
            "detail": f"Embedded file extracted: {path}",
            "severity": "critical",
            "evidence": path,
            "extracted_path": path,
        })
        if path:
            extracted_files.append(path)

    # LSB / steganographic data
    for item in raw.get("lsb_data") or raw.get("steg_findings") or []:
        findings.append({
            "type": "lsb_data",
            "detail": str(item),
            "severity": "high",
            "evidence": str(item),
            "extracted_path": None,
        })

    # Metadata anomalies
    for item in raw.get("metadata") or raw.get("exif_anomalies") or []:
        findings.append({
            "type": "metadata_anomaly",
            "detail": str(item),
            "severity": "low",
            "evidence": str(item),
            "extracted_path": None,
        })

    risk_score = min(10.0, sum(
        {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}.get(f["severity"], 0)
        for f in findings
    ))

    return {
        "analyzer": "steg",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": json.dumps(raw),
        "extracted_files": extracted_files,
    }
```

### Template for Remaining Adapters

Use this skeleton for `recon_adapter.py`, `web_adapter.py`, `url_adapter.py`:

```python
import json

def adapt(raw: dict, pass_number: int, input_data: str) -> dict:
    findings = []

    # TODO: map fields from YOUR old analyzer's response format
    # Example (adjust keys to match actual response):
    # for port in raw.get("open_ports", []):
    #     findings.append({
    #         "type": "port",
    #         "detail": f"Open port: {port}",
    #         "severity": "medium",
    #         "evidence": str(port),
    #     })

    risk_score = min(10.0, sum(
        {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}.get(f.get("severity","info"), 0)
        for f in findings
    ))

    return {
        "analyzer": "REPLACE_WITH_ANALYZER_NAME",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": json.dumps(raw),
    }
```

---

## 8. Updated `compose.yml`

Add the orchestrator service to the existing `compose.yml`. Key points:
- Use `depends_on` so orchestrator waits for analyzers
- All services share a Docker network so the orchestrator can reach them by service name

```yaml
# backend/compose.yml

networks:
  secflow-net:
    driver: bridge

services:

  # ── Existing analyzer services (no changes to their definitions) ────────────

  malware-analyzer:
    build: ./malware-analyzer
    ports:
      - "5001:5001"
    env_file:
      - ./malware-analyzer/.env.example
    networks:
      - secflow-net

  steg-analyzer:
    build: ./steg-analyzer
    ports:
      - "5002:5002"
    networks:
      - secflow-net

  recon-analyzer:
    build: ./recon-analyzer
    ports:
      - "5003:5003"
    env_file:
      - ./recon-analyzer/.env.example
    networks:
      - secflow-net

  url-analyzer:
    build: ./url-analyzer
    ports:
      - "5004:5004"
    networks:
      - secflow-net

  web-analyzer:
    build: ./web-analyzer
    ports:
      - "5005:5005"
    networks:
      - secflow-net

  # ── NEW: Orchestrator service ────────────────────────────────────────────────

  orchestrator:
    build: ./orchestrator
    ports:
      - "5000:5000"
    env_file:
      - .env.example
    environment:
      - MALWARE_ANALYZER_URL=http://malware-analyzer:5001/api/malware-analyzer/
      - STEG_ANALYZER_URL=http://steg-analyzer:5002/api/steg-analyzer/
      - RECON_ANALYZER_URL=http://recon-analyzer:5003/api/recon-analyzer/
      - URL_ANALYZER_URL=http://url-analyzer:5004/api/url-analyzer/
      - WEB_ANALYZER_URL=http://web-analyzer:5005/api/web-analyzer/
    depends_on:
      - malware-analyzer
      - steg-analyzer
      - recon-analyzer
      - url-analyzer
      - web-analyzer
    networks:
      - secflow-net
    volumes:
      - /tmp/secflow_reports:/tmp/secflow_reports   # report output mount
```

---

## 9. API Contracts — All Endpoints

### `POST /api/smart-analyze` (Orchestrator — NEW)

**Request (file upload):**
```
POST /api/smart-analyze?passes=3
Content-Type: multipart/form-data

file: <binary file>
```

**Request (string target):**
```
POST /api/smart-analyze?passes=5
Content-Type: application/json

{ "target": "https://example.com" }
{ "target": "192.168.1.100" }
{ "target": "evil.example.com" }
```

**Response:**
```json
{
  "job_id": "a1b2c3d4",
  "passes_completed": 3,
  "overall_risk_score": 8.5,
  "findings_summary": [
    {
      "analyzer": "steg",
      "pass": 1,
      "input": "/tmp/_suspicious.png",
      "findings": [...],
      "risk_score": 7.0,
      "raw_output": "..."
    },
    ...
  ],
  "report_paths": {
    "json": "/tmp/secflow_reports/a1b2c3d4/report.json",
    "html": "/tmp/secflow_reports/a1b2c3d4/report.html",
    "pdf":  "/tmp/secflow_reports/a1b2c3d4/report.pdf"
  }
}
```

### `POST /api/malware-analyzer/` (Existing Service — Unchanged)

```
POST /api/malware-analyzer/
Content-Type: multipart/form-data

file: <binary/executable>
```

### `POST /api/steg-analyzer/` (Existing Service — Unchanged)

```
POST /api/steg-analyzer/
Content-Type: multipart/form-data

file: <image file>
```

### `POST /api/recon-analyzer/` (Existing Service — Unchanged)

```
POST /api/recon-analyzer/
Content-Type: application/json

{ "target": "192.168.1.1" }
```

### `POST /api/web-analyzer/` (Existing Service — Unchanged)

```
POST /api/web-analyzer/
Content-Type: application/json

{ "url": "https://example.com" }
```

---

## 10. URL Analyzer — What To Do With It

The `url-analyzer` (port 5004) is separate from `web-analyzer`. In SecFlow's route structure, there is no standalone `/api/url-analyzer/` public route.

**Recommended handling:**
- Keep `url-analyzer` running as an internal service (it's in compose.yml)
- The orchestrator calls it internally as `tool: "url"` when the AI engine decides URL analysis is needed
- It is **not** exposed publicly as a standalone route to users
- The AI Decision Engine can route to it the same way it routes to other analyzers

If you want to expose it publicly later, just add it to the route listing — the orchestrator infrastructure already supports it.

---

## 11. Environment Variables

### Root `.env.example` (update this)
```
# Gemini AI (required for orchestrator)
GEMINI_API_KEY=your_gemini_key_here

# Optional integrations
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_vt_key_here

# Analyzer service URLs (Docker Compose resolves these automatically via service names)
# Override these only if running services outside Docker
MALWARE_ANALYZER_URL=http://malware-analyzer:5001/api/malware-analyzer/
STEG_ANALYZER_URL=http://steg-analyzer:5002/api/steg-analyzer/
RECON_ANALYZER_URL=http://recon-analyzer:5003/api/recon-analyzer/
URL_ANALYZER_URL=http://url-analyzer:5004/api/url-analyzer/
WEB_ANALYZER_URL=http://web-analyzer:5005/api/web-analyzer/
```

### `backend/orchestrator/.env.example`
```
GEMINI_API_KEY=your_gemini_key_here
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=

MALWARE_ANALYZER_URL=http://malware-analyzer:5001/api/malware-analyzer/
STEG_ANALYZER_URL=http://steg-analyzer:5002/api/steg-analyzer/
RECON_ANALYZER_URL=http://recon-analyzer:5003/api/recon-analyzer/
URL_ANALYZER_URL=http://url-analyzer:5004/api/url-analyzer/
WEB_ANALYZER_URL=http://web-analyzer:5005/api/web-analyzer/
```

---

## 12. Testing Checklist

Work through this checklist after each migration phase:

### Phase A — Analyzer services verified
- [ ] `docker compose up` brings up all 5 analyzer containers
- [ ] Malware analyzer responds at `http://localhost:5001/api/malware-analyzer/`
- [ ] Steg analyzer responds at `http://localhost:5002/api/steg-analyzer/`
- [ ] Recon analyzer responds at `http://localhost:5003/api/recon-analyzer/`
- [ ] URL analyzer responds at `http://localhost:5004/api/url-analyzer/`
- [ ] Web analyzer responds at `http://localhost:5005/api/web-analyzer/`
- [ ] Each service returns its full response body — document the exact JSON shape

### Phase B — Adapters verified
- [ ] `malware_adapter.adapt(sample_response, 1, "test.exe")` returns correct SecFlow contract shape
- [ ] `steg_adapter.adapt(sample_response, 1, "test.png")` returns correct shape with `extracted_files`
- [ ] `recon_adapter.adapt(sample_response, 1, "8.8.8.8")` returns correct shape
- [ ] `web_adapter.adapt(sample_response, 1, "https://example.com")` returns correct shape
- [ ] All adapters: `risk_score` is between 0.0 and 10.0
- [ ] All adapters: `findings` is a list (even if empty)

### Phase C — Orchestrator service verified
- [ ] `docker compose up orchestrator` starts without errors
- [ ] `GET http://localhost:5000/` returns 200 (health check route optional but recommended)
- [ ] `POST /api/smart-analyze` with a PNG file runs and returns `passes_completed >= 1`
- [ ] `POST /api/smart-analyze` with a URL target runs
- [ ] `POST /api/smart-analyze` with `passes=5` runs the full 5-pass loop (or exits early correctly)
- [ ] Report JSON, HTML, PDF files are written to the output directory

### Phase D — End-to-end pipeline verified
- [ ] PNG with embedded EXE → steg → malware (2+ passes)
- [ ] Malware sample with HTTP callout → malware → web (2+ passes)
- [ ] IP address → recon (1–2 passes)
- [ ] Unknown file type goes through AI fallback classification
- [ ] Early termination works: clean domain → loop exits before max passes
- [ ] All passes are recorded in the Findings Store
- [ ] Report contains summary, risk scores, and recommendations
