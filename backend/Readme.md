# SecFlow — Backend

The backend is a **multi-service Docker Compose application** comprising six microservices: five analyzer services and one Orchestrator service that runs the AI pipeline loop.

---

## Service Overview

| Service | Directory | Port | Public API |
|---|---|---|---|
| Orchestrator (new) | `orchestrator/` | 5000 | `POST /api/smart-analyze` |
| Malware Analyzer | `malware-analyzer/` | 5001 | `POST /api/malware-analyzer/` |
| Steg Analyzer | `steg-analyzer/` | 5002 | `POST /api/steg-analyzer/` |
| Recon Analyzer | `recon-analyzer/` | 5003 | `POST /api/recon-analyzer/` |
| URL Analyzer | `url-analyzer/` | 5004 | Internal only |
| Web Analyzer | `web-analyzer/` | 5005 | `POST /api/web-analyzer/` |

---

## Directory Structure

```
backend/
│
├── orchestrator/                        ← NEW (build this)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes.py                    ← Flask: POST /api/smart-analyze
│   │   ├── orchestrator.py              ← Pipeline loop (HTTP calls to analyzers)
│   │   ├── classifier/
│   │   │   ├── classifier.py
│   │   │   └── rules.py
│   │   ├── ai/
│   │   │   ├── engine.py                ← Gemini tool-calling wrapper
│   │   │   └── keywords.txt
│   │   ├── adapters/                    ← Translate analyzer responses → SecFlow contract
│   │   │   ├── malware_adapter.py
│   │   │   ├── steg_adapter.py
│   │   │   ├── recon_adapter.py
│   │   │   ├── url_adapter.py
│   │   │   └── web_adapter.py
│   │   ├── store/
│   │   │   └── findings_store.py
│   │   └── reporter/
│   │       ├── report_generator.py
│   │       └── pwndoc_schema.json
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
├── compose.yml                          ← Orchestrates all 6 services
└── .env.example                         ← Root env vars (GEMINI_API_KEY etc.)
```

---

## Quick Start

```bash
cd backend

# 1. Copy your .env
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY

# 2. Build and start all services
docker compose up --build

# 3. Run a test analysis
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -F "file=@/path/to/suspicious.png"

# Or with a URL/IP target:
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'
```

---

## Using Individual Analyzers Directly

The analyzer services are also accessible directly (useful for testing):

```bash
# Malware
curl -X POST http://localhost:5001/api/malware-analyzer/ \
  -F "file=@/path/to/sample.exe"

# Steganography
curl -X POST http://localhost:5002/api/steg-analyzer/ \
  -F "file=@/path/to/image.png"

# Reconnaissance
curl -X POST http://localhost:5003/api/recon-analyzer/ \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# Web Vulnerability
curl -X POST http://localhost:5005/api/web-analyzer/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## How the Pipeline Works

1. **`POST /api/smart-analyze`** received by the Orchestrator service.
2. **Classifier** identifies input type using `file` + `python-magic` and selects the first analyzer. Unknown types fall back to Gemini AI.
3. **Orchestrator** calls the selected analyzer via HTTP (e.g., `http://malware-analyzer:5001/...`). Docker Compose resolves service names.
4. The analyzer's response is passed through the corresponding **adapter** (e.g., `malware_adapter.py`) which normalizes it to the SecFlow contract format.
5. Normalized output is stored in the **Findings Store**.
6. **Gemini AI** receives the findings and decides the next analyzer. Loop repeats for N passes (3–5).
7. **Report Generator** sends all accumulated findings to Gemini and renders JSON / PDF / HTML.

See [docs/pipeline-flow.md](../docs/pipeline-flow.md) and [docs/migration.md](../docs/migration.md) for full details.

---

## SecFlow Output Contract

Every adapter must produce a dict with this shape:

```python
{
    "analyzer": str,         # "malware" | "steg" | "recon" | "web" | "url"
    "pass": int,             # 1-indexed loop pass number
    "input": str,            # what was sent to the analyzer
    "findings": list[dict],  # normalized finding objects
    "risk_score": float,     # 0.0 – 10.0
    "raw_output": str,       # raw analyzer response (for AI consumption)
    # steg only:
    "extracted_files": list[str]
}
```

---

## Required Environment Variables

```
GEMINI_API_KEY=           # Required — Gemini AI for routing + report generation
SHODAN_API_KEY=           # Optional — enhanced recon
VIRUSTOTAL_API_KEY=       # Optional — hash lookups

# Set automatically by Docker Compose via service name resolution:
MALWARE_ANALYZER_URL=http://malware-analyzer:5001/api/malware-analyzer/
STEG_ANALYZER_URL=http://steg-analyzer:5002/api/steg-analyzer/
RECON_ANALYZER_URL=http://recon-analyzer:5003/api/recon-analyzer/
URL_ANALYZER_URL=http://url-analyzer:5004/api/url-analyzer/
WEB_ANALYZER_URL=http://web-analyzer:5005/api/web-analyzer/
```

---

## Developer Notes

- **Do not modify existing analyzer service code** to match the SecFlow contract — write/update the adapter in `orchestrator/app/adapters/` instead.
- **Do not import analyzer code directly** into the orchestrator. All analyzer calls go via HTTP.
- The `url-analyzer` is internal — it has no public route and is only callable by the orchestrator.
- See [AGENTS.md](../AGENTS.md) for full agent roles, coding conventions, and contracts.
- See [docs/migration.md](../docs/migration.md) for step-by-step migration instructions.
