# SecFlow — Backend

The backend is a **six-core-service Docker Compose application**: one
TypeScript/LangGraph.js orchestrator and five independent Python analyzer
microservices (plus the Steg analyzer's PostgreSQL, Redis, and worker
containers). The analyzers keep their own HTTP APIs; the orchestrator calls them
over the shared Docker network.

---

## Service Overview

| Service | Source directory | Host port | Container port | Public API |
|---|---|---|---|---|
| Orchestrator | `orchestrator-ts/` | 5000 | 5000 | `POST /api/smart-analyze` |
| Malware Analyzer | `Malware-Analyzer/` | 5001 | 5000 | `POST /api/malware-analyzer/decompile` + `/file-analysis` |
| Steg Analyzer | `Steg-Analyzer/` | 5002 | 5000 | `POST /api/steg-analyzer/upload` |
| Recon Analyzer | `Recon-Analyzer/` | 5003 | 5000 | `POST /api/Recon-Analyzer/scan` + `/footprint` |
| Web Analyzer | `Web-Analyzer/` | 5005 | 5000 | `POST /api/web-analyzer/` |
| Macro Analyzer | `macro-analyzer/` | 5006 | 5000 | `POST /api/macro-analyzer/analyze` |

> All containers listen on port **5000 internally**. Host ports differ.
> There is no `url-analyzer` service — that was a placeholder that was never built.

---

## Directory Structure

```
backend/
│
├── orchestrator-ts/                     ← TypeScript + LangGraph orchestrator (port 5000)
│   ├── src/
│   │   ├── index.ts                     ← Express bootstrap + graceful shutdown
│   │   ├── app.ts                       ← App factory (CORS, logging, routes)
│   │   ├── config.ts                    ← Zod-validated environment
│   │   ├── routes/
│   │   │   ├── analyze.ts               ← POST /api/smart-analyze
│   │   │   ├── health.ts                ← GET /api/health + /api/ready
│   │   │   └── reports.ts               ← GET /api/report/:jobId/:fmt
│   │   ├── classifier/                  ← Deterministic classification + rules
│   │   ├── graph/                       ← LangGraph state, decisions, loop, finalization
│   │   ├── analyzers/                   ← HTTP clients, adapters, validated tools
│   │   ├── pipeline/                    ← Runner, uploads, payload downloader
│   │   ├── security/                    ← SSRF/network guard
│   │   ├── rules/                       ← YARA-X + SIGMA generation and validation
│   │   ├── report/                      ← PWNDoc JSON/HTML builder + narrative
│   │   ├── prompts/                     ← Centralized evidence-isolated prompts
│   │   └── model/                       ← OpenRouter provider + model adapter
│   ├── tests/                           ← Unit, contract, parity, live-gated tests
│   ├── Dockerfile
│   └── package.json
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
└── compose.yml                          ← All services on secflow-net
```

---

## Quick Start

```bash
cd backend

# 1. Copy env file
cp .env.example .env
# Fill in OPENROUTER_API_KEY (required) and VIRUSTOTAL_API_KEY (recommended)
# See .env.example for all model, timeout, and security settings.

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

The response contains `job_id`, `passes_completed`, `overall_risk_score`,
`findings_summary`, `report_paths`, and `report_urls`. Reports are also served at
`GET /api/report/<job_id>/html` and `/json`.

### Local orchestrator development (without rebuilding the container)

```bash
cd backend/orchestrator-ts
npm ci
export OPENROUTER_API_KEY=...
export ALLOW_PRIVATE_TARGETS=false
npm run dev
```

Analyzer URLs default to the Docker-internal hostnames. Override
`ANALYZER_*_URL` when running the orchestrator directly on the host.

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

1. `POST /api/smart-analyze` is received by the orchestrator. `passes` accepts
   `3`, `4`, or `5` and defaults to `3`.
2. The **classifier** identifies the input from magic bytes, file extension, and
   string rules (image → steg, Office/RTF → macro, executable → malware,
   URL → web, IP/domain/email/phone → recon). Unknown inputs go to the model
   with a bounded, untrusted-context file preview.
3. A **LangGraph state graph** runs the analysis loop. After each analyzer pass
   the model receives the current findings/evidence and decides the next
   analyzer tool or finishes. All analyzer tools are validated
   `{ targetId }` calls into a trusted per-run target catalog.
4. Analyzer HTTP responses pass through the matching adapter, which normalises
   them to the SecFlow contract. Results are accumulated in graph state and the
   raw-output store (the model sees bounded evidence, never unbounded dumps).
5. When the model finishes, the orchestrator opportunistically downloads HTTP
   URLs found in evidence through an SSRF-guarded downloader (50 MiB cap,
   per-redirect checks) and routes the payload to a matching analyzer with a
   `payload_downloaded` provenance finding.
6. The loop stops at the requested pass count, model termination, the
   `MODEL_MAX_CYCLES`/`MODEL_MAX_TOOL_CALLS` budgets, or the overall deadline.
7. **YARA-X** compiles generated YARA rules and **SIGMA** rules are structurally
   validated. The **report stage** renders a self-contained PWNDoc HTML report
   plus JSON. Optional narrative text is generated by the same OpenRouter model.

### Failure behavior

- Analyzer failures are recorded as tool errors/structured findings; the run
  continues when other evidence exists.
- If the whole run produces no findings, the API returns `500` rather than
  fabricating a result.
- Missing `OPENROUTER_API_KEY` returns `503`; an overall timeout returns `504`;
  blocked SSRF targets return `400`.

---

## AI Model — OpenRouter

The orchestrator uses **OpenRouter** through the Vercel AI SDK
(`@openrouter/ai-sdk-provider` + `ai`) and runs decisions as a single
LangGraph.js state machine.

- Default model: `nvidia/nemotron-3-ultra-550b-a55b:free`
- Override with `OPENROUTER_MODEL`
- Per-call limit: `MODEL_MAX_TOKENS` (default `2048`)
- Per-run decision budget: `MODEL_MAX_CYCLES` (default `12`)
- Request timeout: `MODEL_TIMEOUT_MS` (default `60000`)

Tool calls are schema-validated with Zod. Model output cannot choose arbitrary
URLs, commands, or files; analyzer tools accept only target ids already present
in the run's target catalog.

---

## SecFlow Findings Contract

Every adapter produces:

```ts
{
  analyzer: "malware" | "steg" | "recon" | "web" | "macro",
  pass: number,              // 1-indexed loop pass number
  input: string,             // what was sent to the analyzer
  findings: Finding[],
  risk_score: number,        // 0.0 – 10.0
  raw_output: string,        // analyzer text retained for evidence/reporting
}
```

Each finding:

```ts
{
  type: string,              // e.g. "malware_detection", "macro_malicious", "av_detection"
  detail: string,            // human-readable description
  severity: "info" | "low" | "medium" | "high" | "critical",
  evidence?: string,         // raw evidence rendered in the HTML report
  extracted_path?: string | null,
}
```

---

## Environment Variables

```env
# backend/.env (copy from .env.example)

OPENROUTER_API_KEY=        # Required — routing, rule generation, report narrative
OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
VIRUSTOTAL_API_KEY=        # Recommended — Malware + Macro VT lookups
GEMINI_API_KEY=            # Optional — analyzer-only AI summary/diagram endpoints

# Orchestrator limits
MODEL_MAX_CYCLES=12
MODEL_MAX_TOKENS=2048
MODEL_TIMEOUT_MS=60000
ANALYZER_TIMEOUT_MS=60000
TOTAL_ANALYSIS_TIMEOUT_MS=600000
MAX_UPLOAD_BYTES=52428800
ALLOW_PRIVATE_TARGETS=false
LOG_LEVEL=info

# Recon
NUMVERIFY_API_KEY=         # Optional — phone number validation
THREATFOX_API_KEY=         # Optional — higher ThreatFox rate limit
ipAPI_KEY=                 # Optional — ip-api.com Pro

# Steg DB
STEG_POSTGRES_PASSWORD=    # Default: secflowpass
```

`ALLOW_PRIVATE_TARGETS=true` is only for local demos/tests. It permits
loopback/private destinations while still requiring HTTP(S) without embedded
credentials. Keep it `false` in production.

---

## Testing

```bash
cd backend/orchestrator-ts

npm run typecheck
npm run lint
npm test
npm run build

# Python-vs-TypeScript parity replay (requires the Python baseline checkout)
SECFLOW_PARITY=1 npx vitest run tests/parity/parity.test.ts
```

Live OpenRouter and analyzer tests are gated by `OPENROUTER_API_KEY` and
`SECFLOW_LIVE_ANALYZERS=1`.

---

## Developer Notes

- **Never modify analyzer service code** to match the SecFlow contract. Update
  the TypeScript adapter in `orchestrator-ts/src/analyzers/adapters/` instead.
- **Never import analyzer code** into the orchestrator. All analyzer calls are
  HTTP requests to their service URLs.
- The `Recon-Analyzer` request body key is `"query"`, not `"target"`.
- The `Recon-Analyzer` API prefix is `/api/Recon-Analyzer` (capital R and A).
- The `Malware-Analyzer` Dockerfile requires `eclipse-temurin:21-jdk-jammy` as
  base image (Ghidra needs JDK 21).
- Reports are written under `REPORTS_DIR/<16-hex job id>/`; uploads and
  downloaded payloads are removed after the run.
- See [AGENTS.md](../AGENTS.md) for full per-service specs and coding conventions.
- See [docs/](../docs/) for architecture, pipeline flow, analyzer docs, and the
  TypeScript migration record.
