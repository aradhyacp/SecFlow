# SecFlow — Backend

The backend is a **six-container Docker Compose application**: one Orchestrator service that runs the AI pipeline loop and five independent analyzer microservices.

---

## Service Overview

| Service | Source directory | Host port | Container port | Public API |
|---|---|---|---|---|
| Orchestrator | `orchestrator/` | 5000 | 5000 | `POST /api/smart-analyze` |
| Malware Analyzer | `Malware-Analyzer/` | 5001 | 5000 | `POST /api/malware-analyzer/decompile` + `/file-analysis` |
| Steg Analyzer | `Steg-Analyzer/` | 5002 | 5000 | `POST /api/steg-analyzer/upload` |
| Recon Analyzer | `Recon-Analyzer/` | 5003 | 5000 | `POST /api/Recon-Analyzer/scan` + `/footprint` |
| Web Analyzer | `Web-Analyzer/` | 5005 | 5000 | `POST /api/web-analyzer/` |
| Macro Analyzer | `macro-analyzer/` | 5006 | 5000 | `POST /api/macro-analyzer/analyze` |

> All containers listen on port **5000 internally**. Host ports differ.  
> There is no `url-analyzer` service \u2014 that was a placeholder that was never built.

---

## Directory Structure

```
backend/
│
├── orchestrator/                        ← Pipeline orchestrator (port 5000)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes.py                    ← Flask: POST /api/smart-analyze
│   │   ├── orchestrator.py              ← Pipeline loop + download-and-analyze
│   │   ├── classifier/
│   │   │   ├── classifier.py            ← file + python-magic detection
│   │   │   └── rules.py                 ← Deterministic routing rules
│   │   ├── ai/
│   │   │   ├── engine.py                ← Groq qwen/qwen3-32b wrapper
│   │   │   └── keywords.txt             ← Fallback grep keyword list
│   │   ├── adapters/                    ← Normalize analyzer responses → SecFlow contract
│   │   │   ├── malware_adapter.py
│   │   │   ├── steg_adapter.py
│   │   │   ├── recon_adapter.py
│   │   │   ├── web_adapter.py
│   │   │   └── macro_adapter.py
│   │   ├── store/
│   │   │   └── findings_store.py
│   │   └── reporter/
│   │       └── report_generator.py      ← PWNDoc HTML + Export PDF button
│   ├── Dockerfile
│   └── requirements.txt
│
├── Malware-Analyzer/                    ← Ghidra + objdump + VirusTotal (port 5001)
├── Steg-Analyzer/                       ← binwalk + zsteg + steghide (port 5002)
├── Recon-Analyzer/                      ← ip-api + ThreatFox + OSINT (port 5003)
├── Web-Analyzer/                        ← HTTP vuln scanner (port 5005)
├── macro-analyzer/                      ← oletools + VirusTotal (port 5006)
│   ├── app/
│   │   ├── analyzer.py                  ← olevba VBA extraction + risk scoring
│   │   ├── routes.py                    ← POST /api/macro-analyzer/analyze
│   │   └── vt.py                        ← VirusTotal API v3 (hash lookup → upload → poll)
│   ├── Dockerfile
│   └── requirements.txt
│
└── compose.yml                          ← All 6 services on secflow-net
```

---

## Quick Start

```bash
cd backend

# 1. Copy env file
cp .env.example .env
# Fill in GROQ_API_KEY (required), VIRUSTOTAL_API_KEY (optional)

# 2. Build and start all services
docker compose up --build

# 3. Analyze a file
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -F "file=@/path/to/suspicious.exe"

# Or an IP / domain:
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# Or a URL:
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com/login"}'
```

The response includes a `report_path` field pointing to the generated HTML report.

---

## Using Individual Analyzers Directly

```bash
# Malware — Ghidra decompile
curl -X POST http://localhost:5001/api/malware-analyzer/decompile \
  -F "file=@sample.exe"

# Malware — VirusTotal lookup
curl -X POST http://localhost:5001/api/malware-analyzer/file-analysis \
  -F "file=@sample.exe"

# Steg
curl -X POST http://localhost:5002/api/steg-analyzer/upload \
  -F "file=@image.png"

# Recon — IP or domain
curl -X POST http://localhost:5003/api/Recon-Analyzer/scan \
  -H "Content-Type: application/json" \
  -d '{"query": "8.8.8.8"}'

# Recon — OSINT footprint (email / phone / username)
curl -X POST http://localhost:5003/api/Recon-Analyzer/footprint \
  -H "Content-Type: application/json" \
  -d '{"query": "user@example.com"}'

# Web
curl -X POST http://localhost:5005/api/web-analyzer/ \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Macro
curl -X POST http://localhost:5006/api/macro-analyzer/analyze \
  -F "file=@invoice.xlsm"
```

---

## How the Pipeline Works

1. `POST /api/smart-analyze` received by the Orchestrator.
2. **Classifier** identifies input type via `file` + `python-magic` and applies deterministic routing rules. Unknown types send the first 100 lines + magic output to Groq AI for classification.
3. For each pass, the **Orchestrator** calls the selected analyzer via HTTP to its Docker-internal URL. All service names resolve on `secflow-net`.
4. The analyzer response is passed through the matching **adapter** (`malware_adapter.py` etc.), which normalises it to the SecFlow contract dict.
5. The normalised result is appended to the **Findings Store**.
6. The **AI Decision Engine** (`engine.py`) extracts concrete IOCs (URLs, IPs, domains) from the full `raw_output` via regex, builds a focused context, and queries Groq `qwen/qwen3-32b` to get `{"next_tool", "target", "reasoning"}`. A rule-based fallback handles Groq failures.
7. If AI returns `next_tool: null` but passes remain, the orchestrator looks for HTTP URLs in `raw_output` → streams downloads (≤50 MB) → routes the payload to the matching analyzer. A `payload_downloaded` finding is always prepended to flag provenance.
8. Loop runs until max passes, early termination by AI, or no downloadable payloads remain.
9. **Report Generator** calls Groq once more for an executive summary, then renders a self-contained PWNDoc HTML report with a one-click **Export PDF** button (browser print-to-PDF).

---

## AI Model — Groq `qwen/qwen3-32b`

The AI Decision Engine uses **Groq API** with model `qwen/qwen3-32b` via the OpenAI-compatible interface (`base_url="https://api.groq.com/openai/v1"`).

The system message is set to `/no_think` — a Qwen3 feature that disables chain-of-thought reasoning for faster, direct responses. This is important for routing decisions that happen on every pipeline pass.

The engine does **not** use OpenAI function-calling / tool schemas. Instead it instructs the model via the prompt to return a plain JSON object:
```json
{"next_tool": "malware" | "steg" | "recon" | "web" | "macro" | null, "target": "...", "reasoning": "..."}
```

A regex/rule-based fallback activates if the model returns non-JSON or an empty response.

---

## SecFlow Findings Contract

Every adapter must produce:

```python
{
    "analyzer":   str,         # "malware" | "steg" | "recon" | "web" | "macro"
    "pass":       int,         # 1-indexed loop pass number
    "input":      str,         # what was sent to the analyzer
    "findings":   list[dict],  # list of finding objects
    "risk_score": float,       # 0.0 – 10.0
    "raw_output": str,         # full text output (AI reads this for IOC extraction)
}
```

Each `finding` object:
```python
{
    "type":     str,   # e.g. "malware_detection", "macro_malicious", "av_detection" …
    "detail":   str,   # human-readable description
    "severity": str,   # "info" | "low" | "medium" | "high" | "critical"
    "evidence": str,   # raw evidence — rendered intelligently in HTML report
}
```

---

## Required Environment Variables

```
# backend/.env (copy from .env.example)

GROQ_API_KEY=             # Required — AI routing + report summary
VIRUSTOTAL_API_KEY=       # Optional — Malware Analyzer + Macro Analyzer VT lookups
GEMINI_API_KEY=           # Optional — Malware Analyzer AI summary/diagram endpoints only

# Recon
NUMVERIFY_API_KEY=        # Optional — phone number validation
THREATFOX_API_KEY=        # Optional — higher ThreatFox rate limit
ipAPI_KEY=                # Optional — ip-api.com Pro

# Steg DB
STEG_POSTGRES_PASSWORD=   # Default: secflowpass

# Loop size (default 3, max 5)
MAX_PASSES=3
```

---

## Developer Notes

- **Never modify analyzer service code** to match the SecFlow contract. Write the adapter instead.
- **Never import analyzer code** into the orchestrator. All analyzer calls are `requests.post()` over HTTP.
- The `Recon-Analyzer` request body key is `"query"`, not `"target"`.  
- The `Recon-Analyzer` API prefix is `/api/Recon-Analyzer` (capital R and A).
- The `Malware-Analyzer` Dockerfile requires `eclipse-temurin:21-jdk-jammy` as base image (Ghidra needs JDK 21).
- See [AGENTS.md](../AGENTS.md) for full per-service specs and coding conventions.
- See [docs/](../docs/) for architecture, pipeline flow, and analyzer docs.
