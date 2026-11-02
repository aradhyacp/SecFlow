# SecFlow — Implementation Guide

> **Historical note:** this guide describes the pre-migration Python/Groq
> orchestrator. The active orchestrator is the TypeScript/LangGraph service in
> `backend/orchestrator-ts/`; see
> [ts-migration/11-cutover.md](ts-migration/11-cutover.md) and
> [architecture.md](architecture.md) for the current implementation. The
> analyzer service APIs documented below are still accurate.

This guide documents the implementation of SecFlow: key patterns, code structure, and how the pipeline actually works in practice.

---

## Table of Contents

1. [Service Overview](#1-service-overview)
2. [Orchestrator Structure](#2-orchestrator-structure)
3. [How AI Routing Works (Not Real Tool-Calling)](#3-how-ai-routing-works)
4. [Writing a New Analyzer Adapter](#4-writing-a-new-analyzer-adapter)
5. [Environment Variables Reference](#5-environment-variables-reference)
6. [Running Locally](#6-running-locally)

---

## 1. Service Overview

SecFlow is deployed as 6 Docker services. Five are analyzer microservices that run independently. One is the Orchestrator, which contains all routing and reporting logic.

| Service | Directory | Host Port | Container Port |
|---|---|---|---|
| orchestrator | `backend/orchestrator/` | 5000 | 5000 |
| malware-analyzer | `backend/Malware-Analyzer/` | 5001 | 5000 |
| steg-analyzer | `backend/Steg-Analyzer/` | 5002 | 5000 |
| recon-analyzer | `backend/Recon-Analyzer/` | 5003 | 5000 |
| web-analyzer | `backend/Web-Analyzer/` | 5005 | 5000 |
| macro-analyzer | `backend/macro-analyzer/` | 5006 | 5000 |

The `compose.yml` in `backend/` manages all services.

---

## 2. Orchestrator Structure

```
backend/orchestrator/
  app/
    __init__.py            <- create_app() factory
    routes.py              <- POST /api/smart-analyze
    orchestrator.py        <- main pipeline loop + download-and-analyze
    classifier/
      classifier.py        <- python-magic MIME detection
      rules.py             <- deterministic routing rules (first match wins)
    ai/
      engine.py            <- Groq client, artifact extraction, fallback
      keywords.txt         <- fallback keyword list for rule-based routing
    adapters/
      malware_adapter.py
      steg_adapter.py
      recon_adapter.py
      web_adapter.py
      macro_adapter.py
    store/
      findings_store.py    <- append-only list, get_all()
    reporter/
      report_generator.py  <- PWNDoc HTML report, Groq summary
  Dockerfile
  requirements.txt
  .env.example
```

---

## 3. How AI Routing Works

**SecFlow does NOT use real function-calling (tool-calling schemas).** Instead, the AI engine uses a prompt that explicitly instructs the model to return a JSON object.

### Step-by-Step

#### Step 1: Artifact extraction
Before calling Groq, `engine.py` regex-scans the full `raw_output` string for:
- HTTP/S URLs
- IPv4 addresses
- Domain names

These are deduplicated and filtered (removing localhost, pypi.org, etc.).

#### Step 2: Build focused context
The engine assembles a context string:
```
Extracted artifacts from analyzer output:
  URLs: https://evil.sh/drop.exe
  IPs:  185.220.101.50
  Domains: evil.sh

Recent raw output (excerpt):
  ... (first 2000 chars of raw_output) ...
```

#### Step 3: Call Groq
```python
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1",
)

prompt = f"""
You are a threat analysis routing engine. Given the output of a security analyzer,
decide which analyzer to run next. Available analyzers: malware, steg, recon, web, macro.

Respond ONLY with valid JSON in this exact format:
{{"next_tool": "analyzer_name_or_null", "target": "exact_value_to_pass", "reasoning": "brief explanation"}}

If no further analysis is needed, use null for next_tool.

Context:
{context}
"""

response = client.chat.completions.create(
    model="qwen/qwen3-32b",
    messages=[
        {{"role": "system", "content": "/no_think"}},
        {{"role": "user",   "content": prompt}},
    ],
    temperature=0.1,
)
text = response.choices[0].message.content
```

The `/no_think` system message disables Qwen3's chain-of-thought block for speed.

#### Step 4: Parse JSON response
```python
import json, re

# Strip markdown code fences if present
text = re.sub(r'^```json\s*|\s*```$', '', text.strip())
decision = json.loads(text)
# decision = {"next_tool": "recon", "target": "185.220.101.50", "reasoning": "..."}
```

#### Step 5: Fallback
If Groq returns non-JSON or an error:
1. Grep `raw_output` against `keywords.txt` (one keyword per line).
2. Apply a rule-based lookup table: e.g., if "PE32" or "MZ header" matched → `malware`; if "IPv4" address matched → `recon`; etc.
3. If no rule matches → return `{"next_tool": null, "reasoning": "fallback: no match"}`.

---

## 4. Writing a New Analyzer Adapter

All adapters live in `orchestrator/app/adapters/`. They translate native analyzer JSON into the SecFlow contract.

**Contract:**
```python
{
    "analyzer":   str,         # analyzer name
    "pass":       int,         # pass number (1-indexed)
    "input":      str,         # the value passed in
    "findings":   list[dict],  # list of finding objects
    "risk_score": float,       # 0.0 – 10.0
    "raw_output": str,         # full text for AI consumption
}
```

**Finding object:**
```python
{
    "type":     str,    # e.g. "malware_detection"
    "detail":   str,    # human-readable description
    "severity": str,    # "info" | "low" | "medium" | "high" | "critical"
    "evidence": str,    # raw evidence string
}
```

**Minimal adapter template:**
```python
from typing import Any


def adapt(raw: dict[str, Any], pass_num: int, input_value: str) -> dict[str, Any]:
    findings = []
    risk_score = 0.0

    # --- parse raw response and build findings ---
    # raw is the native JSON returned by the analyzer service

    return {
        "analyzer":   "myanalyzer",
        "pass":       pass_num,
        "input":      input_value,
        "findings":   findings,
        "risk_score": min(10.0, risk_score),
        "raw_output": str(raw),
    }
```

**Register in orchestrator.py:**
```python
from app.adapters import myanalyzer_adapter

# In the analyzer dispatch block:
elif tool == "myanalyzer":
    resp = requests.post(f"{_MYANALYZER_BASE}/analyze",
                         files={"file": open(input_value, "rb")}, timeout=60)
    result = myanalyzer_adapter.adapt(resp.json(), pass_num, input_value)
```

---

## 5. Environment Variables Reference

Create `backend/.env` (copy from `backend/.env.example`):

```
# Orchestrator AI
GROQ_API_KEY=gsk_...

# Malware Analyzer
VIRUSTOTAL_API_KEY=...

# Macro Analyzer  
VIRUSTOTAL_API_KEY=...       # same or different VT key

# Recon Analyzer (all optional — free tier works without them)
NUMVERIFY_API_KEY=...        # phone number validation
THREATFOX_API_KEY=...        # higher rate limit
ipAPI_KEY=...                # ip-api.com Pro

# Web / Malware internal Gemini features (optional, unrelated to orchestrator)
GEMINI_API_KEY=...
```

`VIRUSTOTAL_API_KEY` is injected into both `malware-analyzer` and `macro-analyzer` containers via the compose environment blocks.

---

## 6. Running Locally

**Start all services:**
```bash
cd backend
docker compose up --build
```

**First build is slow** — the Malware Analyzer container downloads Ghidra 12.0.1 (~500 MB) and installs JDK 21. Subsequent builds use Docker layer cache.

**Submit a file for analysis:**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -F "file=@/path/to/sample.exe" \
  -F "passes=4"
```

**Submit a URL:**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "passes": 3}'
```

**Submit an IP or domain:**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "185.220.101.50"}'
```

**Response:**
```json
{
  "job_id": "abc123",
  "report_path": "/app/reports/abc123.html",
  "risk_score": 9.2,
  "passes_completed": 4,
  "analyzers_used": ["macro", "web", "malware", "recon"]
}
```

The HTML report is written to `/app/reports/` inside the orchestrator container. Mount a host volume to persist reports across container restarts.

**Check individual analyzer health:**
```bash
curl http://localhost:5001/api/malware-analyzer/health
curl http://localhost:5002/api/steg-analyzer/health
curl http://localhost:5003/api/Recon-Analyzer/health
curl http://localhost:5005/api/web-analyzer/health
curl http://localhost:5006/api/macro-analyzer/health
```

---

## Key Design Decisions

### Why no direct imports across services

Each analyzer is a separate Docker container with its own Python environment and dependencies. The Orchestrator imports nothing from analyzer directories — it only calls them via HTTP. This means:
- Analyzer containers can be restarted independently without affecting the Orchestrator.
- Analyzer services can be written in any language in the future.
- Adapter functions absorb any API changes without touching analyzer code.

### Why adapters are in the Orchestrator

Adapters translate each service's native JSON into the SecFlow contract. They live inside the Orchestrator rather than the analyzer services because:
- Analyzer services don't know about the SecFlow pipeline contract.
- If an analyzer's output format changes, only its adapter changes — not the pipeline loop.

### Why the report is pure Python HTML

No Jinja2 templates, no PDF generation libraries. The report generator uses Python f-strings to produce a self-contained HTML file. The "Export PDF" button calls `window.print()` in the browser, which exports to PDF natively. This eliminates two heavy dependencies (`fpdf2`, `jinja2`) and makes the report renderer testable without a browser.
