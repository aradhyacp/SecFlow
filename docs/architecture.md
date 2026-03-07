# SecFlow — System Architecture

---

## High-Level Component Diagram

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │                     SecFlow — Docker Compose Network                         │
 │                                                                              │
 │  ┌─────────────┐   POST /api/smart-analyze                                  │
 │  │  User /     │──────────────────────────────────────────────────────┐     │
 │  │  Frontend   │                                                      │     │
 │  └─────────────┘                                                      ▼     │
 │                              ┌──────────────────────────────────────────┐   │
 │                              │   Orchestrator Service  (port 5000)      │   │
 │                              │                                          │   │
 │                              │  ┌──────────────────────────────────┐   │   │
 │                              │  │  Input Classifier                │   │   │
 │                              │  │  (file cmd + python-magic)       │   │   │
 │                              │  └──────────────┬───────────────────┘   │   │
 │                              │                 │  first analyzer        │   │
 │                              │  ┌──────────────▼───────────────────┐   │   │
 │                              │  │  AI Decision Engine (Gemini)     │   │   │
 │                              │  │  engine.py + keywords.txt        │   │   │
 │                              │  └──────────────┬───────────────────┘   │   │
 │                              │                 │  next_tool             │   │
 │                              │  ┌──────────────▼───────────────────┐   │   │
 │                              │  │  Pipeline Loop (orchestrator.py) │   │   │
 │                              │  └──────────────┬───────────────────┘   │   │
 │                              │                 │  HTTP calls             │   │
 │                              └─────────────────┼─────────────────────────┘   │
 │                                                │                             │
 │              ┌─────────────────────────────────┴──────────────┐             │
 │              │          Analyzer Services (Docker network)     │             │
 │              │                                                 │             │
 │    ┌─────────▼────────┐  ┌──────────────────┐  ┌─────────────▼──────────┐  │
 │    │ malware-analyzer │  │  steg-analyzer   │  │    recon-analyzer      │  │
 │    │   port 5001      │  │   port 5002      │  │      port 5003         │  │
 │    └──────────────────┘  └──────────────────┘  └────────────────────────┘  │
 │                                                                              │
 │    ┌──────────────────┐  ┌──────────────────┐                               │
 │    │  url-analyzer    │  │  web-analyzer    │                               │
 │    │  port 5004       │  │   port 5005      │                               │
 │    │  (internal only) │  └──────────────────┘                               │
 │    └──────────────────┘                                                     │
 │                                                                              │
 │              ┌──────────────────────────────────────────────────────────┐   │
 │              │   Back inside Orchestrator after each analyzer call      │   │
 │              │                                                          │   │
 │              │  Adapter fn (malware/steg/recon/web_adapter.py)          │   │
 │              │    → normalize response → SecFlow contract dict          │   │
 │              │  Findings Store (findings_store.py)                      │   │
 │              │    → append(finding)                                     │   │
 │              └──────────────────────────────────────────────────────────┘   │
 │                                                                              │
 │              ┌──────────────────────────────────────────────────────────┐   │
 │              │   Report Generator (end of loop)                        │   │
 │              │   Findings Store → Gemini AI → JSON / PDF / HTML        │   │
 │              └──────────────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Descriptions

### Orchestrator Service (NEW — port 5000)
- **What it is:** A new Flask microservice, the only net-new code in SecFlow.
- **Exposes:** `POST /api/smart-analyze`
- **Contains:** Input Classifier, AI Decision Engine, Adapters, Findings Store, Report Generator — all as internal modules.
- **How it calls analyzers:** Via HTTP to Docker-internal service URLs (e.g., `http://malware-analyzer:5001/api/malware-analyzer/`). Docker Compose resolves service names.

### Input Classifier
- **Role:** Determines input type and selects the first analyzer. Lives inside the Orchestrator service.
- **Primary method:** `file` command (system) + `python-magic` (Python library).
- **Output:** One of `[ "malware", "steg", "recon", "web", "url", "unknown" ]`.
- **Fallback:** Passes `file`/`python-magic` output plus `head -100` of the file to the AI Decision Engine when type is `"unknown"`.

### AI Decision Engine
- **Role:** AI router. Given the output of the most recent analyzer, returns the next analyzer name or a termination signal. Lives inside the Orchestrator service.
- **Model:** Google Gemini (tool-calling mode).
- **Fallback strategy:**
  1. Pass analyzer's `raw_output` to Gemini → get `next_tool`.
  2. If output too large → grep `keywords.txt` matches → pass matched lines to Gemini.
  3. If still unclear → pass full output (truncated to 4000 chars).
- **Output:** `{ "next_tool": str | null, "reasoning": str }`.

### Adapters
- **Role:** Translation layer between each analyzer's native response format and the SecFlow findings contract.
- **Location:** `orchestrator/app/adapters/<name>_adapter.py` — one per analyzer.
- **Why they exist:** Analyzer services return their own JSON shapes. Adapters absorb format differences without touching analyzer code.

### Analyzer Services (5 containers)
Each is an independent Docker microservice called by the Orchestrator via HTTP POST.

| Service | Port | Transport | Input |
|---|---|---|---|
| `malware-analyzer` | 5001 | `multipart/form-data` | EXE / binary file |
| `steg-analyzer` | 5002 | `multipart/form-data` | Image file |
| `recon-analyzer` | 5003 | `application/json` `{"target": "ip_or_domain"}` | IP / domain |
| `url-analyzer` | 5004 | `application/json` `{"url": "..."}` | URL (internal only) |
| `web-analyzer` | 5005 | `application/json` `{"url": "..."}` | URL |

### Findings Store
- **Role:** Append-only accumulator for all adapter-normalized outputs across all loop passes. Lives inside the Orchestrator service.
- **Interface:** `append(finding: dict)`, `get_all() -> list[dict]`, `to_json() -> str`.
- **Persistence:** In-memory during a pipeline run; serialized to disk as `findings.json` after completion.

### Report Generator
- **Role:** Takes the full Findings Store, formats via Gemini into a PWNDoc report. Lives inside the Orchestrator service.
- **Output formats:** JSON, PDF (fpdf2), HTML (Jinja2).
- **Validates** Gemini-formatted output against `pwndoc_schema.json` before writing.

---

## Data Flow Summary

```
User POST /api/smart-analyze
  → Orchestrator (port 5000)
      → Classifier (pass 1 only, no AI)
          [rule match]  → HTTP POST → Analyzer Service
          [unknown]     → AI Engine → Analyzer Service

      Loop (pass 2..N):
        HTTP POST → Analyzer Service → raw response
        → Adapter → SecFlow contract dict
        → Findings Store.append()
        → AI Engine → next_tool (or null → break)

      End of loop:
        Findings Store.to_json() → Report Generator
        → Gemini AI → PWNDoc → JSON + PDF + HTML
```

---

## Docker Compose Network

All services communicate over a shared Docker bridge network (`secflow-net`). The Orchestrator reaches analyzers by Docker service name:

| Orchestrator calls | Resolves to |
|---|---|
| `http://malware-analyzer:5001` | malware-analyzer container |
| `http://steg-analyzer:5002` | steg-analyzer container |
| `http://recon-analyzer:5003` | recon-analyzer container |
| `http://url-analyzer:5004` | url-analyzer container |
| `http://web-analyzer:5005` | web-analyzer container |

Analyzer service URLs can be overridden via environment variables (`MALWARE_ANALYZER_URL`, etc.) for local development without Docker.
