# AGENTS.md — SecFlow

This file defines the agent architecture for SecFlow and provides instructions for AI coding assistants (GitHub Copilot, etc.) working in this repository.

---

## Project Context

**SecFlow** is an automated threat analysis pipeline. Its core is a TypeScript/Node.js orchestrator built on a single LangGraph.js state graph. It routes any input (file, URL, IP, domain, image) through specialized Python analyzer microservices over HTTP, uses an OpenRouter-hosted model for evidence-based routing and rule/report generation, and produces PWNDoc reports.

The backend is the primary focus. The frontend is not under active development; preserve its existing API contract.

---

## Agent Roles

SecFlow's runtime pipeline is composed of the following agents/workers:

---

### 1. Pipeline Orchestrator

**File location:** `backend/orchestrator-ts/`
**Responsibility:**
- Express service exposing `POST /api/smart-analyze`, `GET /api/health`, `GET /api/ready`, and `GET /api/report/:jobId/:fmt`.
- Runs one LangGraph.js state graph (`src/graph/`) that classifies input, runs the first deterministic analyzer, then loops through bounded model decisions and analyzer tools.
- Maintains run state: pass count, model/tool budgets, target catalog, evidence store, termination reason.
- Accumulates every pass in graph state plus the run-scoped raw-output store.
- Runs YARA-X, SIGMA, and report stages after the loop and returns the legacy API response shape.

**Key behaviors:**
- Loop runs for a user-configured max (3, 4, or 5 passes) and stops early when the model returns `finish`.
- Model/tool calls are capped by `MODEL_MAX_CYCLES`, `MODEL_MAX_TOOL_CALLS`, per-call timeouts, and `TOTAL_ANALYSIS_TIMEOUT_MS`.
- Must never call AI on the first pass if a deterministic rule applies.
- Is invoked through the TypeScript runner only; analyzer services remain separate containers.

---

### 2. Input Classifier

**File location:** `backend/orchestrator-ts/src/classifier/`
**Responsibility:**
- Identifies file input from magic bytes, MIME hints, and extension (`sniff.ts`, `rules.ts`).
- Identifies string input with the existing routing regexes.
- Applies deterministic routing rules to select the first analyzer:
  - Image (PNG, JPG, BMP, GIF…) → Steganography Analyzer
  - Office / OLE2 / OpenXML / RTF document → Macro Analyzer
  - Executable / PE / ELF / Mach-O / binary → Malware Analyzer
  - URL string → Web Vulnerability Analyzer
  - IP address / domain / email / phone → Reconnaissance Analyzer
- Fallback: if the type is ambiguous or unknown, exposes the applicable analyzer tools to the model and includes a bounded, untrusted file-head preview in the prompt.

**Key behaviors:**
- No AI is invoked on the first pass when a deterministic rule matches.
- URL rules are checked before domain rules.
- Uploads are never sent to the model; only the bounded preview and evidence summaries are.

---

### 3. AI Decision Engine

**File location:** `backend/orchestrator-ts/src/model/` and `backend/orchestrator-ts/src/graph/decision.ts`
**Responsibility:**
- Wraps OpenRouter through the Vercel AI SDK (`@openrouter/ai-sdk-provider` + `ai`).
- Takes the current findings/evidence summary and returns a tool call (`analyze_malware`, `analyze_steg`, `analyze_recon`, `analyze_web`, `analyze_macro`, `generate_yara`, `generate_sigma`, `generate_report`) or `finish`.
- Uses structured-output schemas and re-validates every decision in the graph.

**Key behaviors:**
- Analysis tools accept only `{ targetId }`; ids must resolve in the trusted per-run target catalog.
- `finish` terminates the loop; the enum only exposes tools available for the current state.
- Evidence comes from the run-scoped raw-output store; the model never receives unbounded analyzer dumps or raw sample bytes.
- Prompts live in `backend/orchestrator-ts/src/prompts/` and wrap analyzer evidence in `<untrusted_evidence>` boundaries.

---

### 4. Malware Analyzer

**Service location:** `backend/Malware-Analyzer/` — source code lives here, directory name is capitalized
**Docker service name:** `malware-analyzer`
**Container port:** `5000` (internal); mapped to host port `5001` in SecFlow `compose.yml`
**Internal Docker URL:** `http://malware-analyzer:5000/api/malware-analyzer/`
**Base image:** `eclipse-temurin:21-jdk-jammy` — JDK 21 is mandatory for `pyghidra` to start the Ghidra JVM
**Production server:** `gunicorn` with 2 workers, 300s timeout

**Responsibility:**
- Analyzes executables, PE binaries, and extracted binary payloads as an independent HTTP microservice.
- Performs three-layer analysis: Ghidra 12.0.1 decompilation (via `pyghidra`), `objdump` disassembly, and VirusTotal API v3 threat intelligence.
- Optionally generates a Gemini AI narrative summary or Mermaid execution-flow diagram.
- Returns its own native JSON; the Orchestrator's `malware_adapter.py` translates it to the SecFlow contract.

**Real API endpoints (all under `/api/malware-analyzer/`):**

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/health` | Health check — returns `{"status": "healthy"}` |
| `POST` | `/decompile` | Ghidra decompilation + `objdump -d` disassembly |
| `POST` | `/file-analysis` | VirusTotal API v3 upload + analysis report |
| `POST` | `/ai-summary` | Ghidra + VT context → Gemini text summary |
| `POST` | `/diagram-generator` | Ghidra + VT context → Gemini Mermaid flow diagram |

> **There is no bare `POST /api/malware-analyzer/` route.** The orchestrator must call `/decompile` and `/file-analysis` individually.

**How the Orchestrator calls it (two requests, merged before adapting):**
```python
# Call 1 — VirusTotal threat intel (timeout 60s)
requests.post("http://malware-analyzer:5000/api/malware-analyzer/file-analysis",
              files={"file": open(path, "rb")}, timeout=60)

# Call 2 — Ghidra decompile + objdump (timeout 180s — Ghidra analysis is slow)
requests.post("http://malware-analyzer:5000/api/malware-analyzer/decompile",
              files={"file": open(path, "rb")}, timeout=180)
```
Both responses are merged into `{"vt": <file-analysis resp>, "decompile": <decompile resp>}` before being passed to `malware_adapter.adapt()`.

**Supported file extensions:** `exe`, `dll`, `so`, `elf`, `bin`, `o`, `out`
(Files with other extensions return HTTP 400. The orchestrator must rename extracted files to `.bin` if needed.)

**Max file size:** 50 MB

**Analysis tools used internally:**
- `pyghidra==2.0.1` + Ghidra 12.0.1 — full decompilation and auto-analysis of all binary functions
- `objdump -d` (binutils) — assembly-level disassembly
- VirusTotal API v3 — 70+ AV engine detections, behavioral tags, file stats
- `google-genai` (`gemini-3-flash-preview`) — AI summary and diagram (used only by `/ai-summary` and `/diagram-generator`; the orchestrator does NOT call these)

**What this service does NOT use:** YARA rules, `pefile`, `hashlib`, `strings` command — these are in the planning docs only.

**Required environment variables:**
- `VIRUSTOTAL_API_KEY` — required for `/file-analysis`; endpoint fails gracefully if absent
- `GEMINI_API_KEY` — required for `/ai-summary` and `/diagram-generator` only
- `PORT` — defaults to `5000`

**Resource requirements:** Memory limit **4 GB** minimum (Ghidra JVM is memory-heavy).

**Adapter input shape:**
```python
# malware_adapter.adapt() receives:
raw = {
    "vt": {         # response from /file-analysis
        "success": bool,
        "filename": str,
        "report": {
            "data": {
                "attributes": {
                    "stats": {"malicious": int, "suspicious": int, "undetected": int, ...},
                    "results": {"<EngineName>": {"category": str, "result": str, ...}, ...}
                }
            }
        }
    },
    "decompile": {  # response from /decompile
        "success": bool,
        "filename": str,
        "decompiled": str,   # Ghidra C pseudo-code for all functions
        "objdump": str       # raw objdump -d output
    }
}
```

**Output contract (after adapter):** `{ "analyzer": "malware", "pass": N, "input": str, "findings": [...], "risk_score": 0.0–10.0, "raw_output": str }`

**Full integration details:** See [docs/Malware-Analyzer-Orchestration.md](docs/Malware-Analyzer-Orchestration.md)

---

### 5. Steganography Analyzer

**Service location:** `backend/steg-analyzer/`
**Docker service:** `steg-analyzer` — runs at `http://steg-analyzer:5002/api/steg-analyzer/`
**Responsibility:**
- Analyzes image files for hidden/embedded data as an independent HTTP microservice.
- Attempts multiple steg-detection techniques (LSB analysis, metadata inspection, embedded file extraction).
- Returns its own native JSON response; the Orchestrator's `steg_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://steg-analyzer:5002/api/steg-analyzer/", files={"file": open(path, "rb")})
```
**Output contract (after adapter):** `{ "analyzer": "steg", "pass": N, "findings": [...], "extracted_files": [...], "risk_score": 0-10 }`

---

### 6. Reconnaissance Analyzer

**Service location:** `backend/Recon-Analyzer/` — source code under `src/`
**Docker service name:** `recon-analyzer`
**Container name:** `recon-analyzer-api` (in standalone compose); use `recon-analyzer` in SecFlow compose
**Container port:** `5000` (internal); mapped to host port `5003` in SecFlow `compose.yml`
**Internal Docker URL:** `http://recon-analyzer:5000/api/Recon-Analyzer/`
**Base image:** `python:3.12-slim`
**System deps:** `build-essential` only (lightweight — no JVM, no heavy downloads)
**Production server:** `gunicorn` with 2 workers, 120s timeout — CMD: `gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 120 main:app`
**API prefix:** `/api/Recon-Analyzer` (capital R and A — must be exact)
**CORS:** Wildcard `*` — all origins, all methods allowed
**Dockerfile:** Named `DockerFile` (capital F) on disk — compose must use `dockerfile: DockerFile`

**Responsibility:**
- Performs threat intelligence and OSINT reconnaissance on IPs, domains, emails, phone numbers, and usernames as an independent HTTP microservice.
- Two distinct modes: **scan** (IP/domain threat intel) and **footprint** (email/phone/username OSINT).
- Returns its own native JSON; the Orchestrator's `recon_adapter.py` translates it to the SecFlow contract.

**Real API endpoints (all under `/api/Recon-Analyzer/`):**

| Method | Route | Purpose | Input |
|---|---|---|---|
| `GET` | `/` or `/api/Recon-Analyzer/` | Home — lists all endpoints | None |
| `GET` | `/health` | Health check | None |
| `POST` | `/scan` | IP/domain threat intel | `{"query": "ip_or_domain"}` |
| `POST` | `/footprint` | Email/phone/username OSINT | `{"query": "email_or_phone_or_username"}` |

> **The request body key is `query`, not `target`.** Generic docs assumed `{"target": "..."}` — the real service uses `{"query": "..."}`.

**How the Orchestrator calls it:**
```python
# For IP or domain (primary pipeline path)
requests.post("http://recon-analyzer:5000/api/Recon-Analyzer/scan",
              json={"query": ip_or_domain}, timeout=60)

# For email/phone/username OSINT (secondary — triggered by AI if previous pass surfaces an email)
requests.post("http://recon-analyzer:5000/api/Recon-Analyzer/footprint",
              json={"query": email_or_username}, timeout=60)
```

**Input auto-detection logic in `/scan` (exact regexes from `main.py`):**
```python
IP_REGEX    = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
DOMAIN_REGEX = r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
```
- Valid IPv4 → runs `ipapi`, `talos`, `tor` (IP-only checks)
- Valid domain → DNS resolves to IP → runs `ipapi` + `talos` + `tor` on resolved IP, then `tranco` + `threatfox` on the domain string
- Invalid format → returns `400 {"error": "Invalid IP or domain format."}`
- Unresolvable domain → returns `400 {"error": "Unable to resolve domain: <domain>"}`

**Input auto-detection logic in `/footprint`:**
```python
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PHONE_REGEX = r'^\+?[0-9]\d{1,14}$'
```
- Matches email regex → `type: "email"` → calls `checkEmail()` from `xposedornot.py`
- Matches phone regex → `type: "phone"` → calls `validate_phone_number()` from `phone.py`
- Neither match → `type: "username"` → calls `sagemode_wrapper()` from `username.py`

**Analysis modules wired into `main.py`:**

| Module | File | External API | What it returns |
|---|---|---|---|
| `ipapi` | `attack/ipapi.py` | `ip-api.com/batch` (POST) + `edns.ip-api.com/json` (GET) | `{ip_info: [...], dns_info: {...}}` — country, ISP, ASN, city, timezone |
| `talos` | `attack/talos.py` | Local `src/media/talos.txt` (auto-downloads from `snort.org/downloads/ip-block-list`) | `{blacklisted: bool}` |
| `tor` | `attack/tor.py` | Local `src/media/tor.txt` (auto-downloads from `check.torproject.org/exit-addresses`, parses IPs via regex) | `{is_tor_exit: bool}` |
| `tranco` | `attack/tranco.py` | `tranco-list.eu/api/ranks/domain/{query}` (GET) | `{found: bool, rank: int}` — domains only |
| `threatfox` | `attack/threatfox.py` | `threatfox-api.abuse.ch/api/v1/` (POST, `{"query":"search_ioc","search_term":...}`) — returns **first IOC match only** | `{found: bool, id, ioc, threat_type, malware, confidence_level, reference, link}` — domains only |
| `xposedornot` | `osint/xposedornot.py` | Two calls: `api.xposedornot.com/v1/check-email/{email}` then `api.xposedornot.com/v1/breach-analytics?email={email}` | `{exposed: bool, breach_count, breaches: [...], password_strength: [...], risk: {...}}` |
| `phone` | `osint/phone.py` | `apilayer.net/api/validate` (GET) via NumVerify | `{valid: bool, country_code, country_name, location, carrier, line_type}` |
| `username` | `osint/username.py` | Multithreaded HTTP scraping (Sagemode class) — 15s timeout per thread, uses `osint/sites.py` list | `[{site: str, url: str}, ...]` |

**Files that exist but are NOT imported or used in `main.py` — do NOT include in adapter:**
- `attack/whoisripe.py` — standalone RIPE database lookup; has a bare `print()` at module level (dev script only)
- `attack/onyphe.py` — Onyphe.io API; has a bare `print()` at module level (dev script only); uses `onypheAPI_KEY` env var
- `attack/tweetfeeds.py` — completely empty file, no implementation
- `src/cli.py` — CLI entrypoint for manual testing; not used by the Flask app

**`/scan` response shape:**
```json
{
  "query": "8.8.8.8",
  "ipapi":    { "ip_info": [{"status":"success","country":"US","isp":"Google LLC","as":"AS15169 Google LLC",...}], "dns_info": {...} },
  "talos":    { "blacklisted": false },
  "tor":      { "is_tor_exit": false },
  "tranco":   { "found": true, "rank": 1 },         // domains only — absent for plain IP
  "threatfox": { "found": true, "malware": "MintsLoader", "confidence_level": 100, ... }  // domains only — absent for plain IP
}
```

**`/footprint` response shapes:**
```json
// Email
{ "query": "user@example.com", "type": "email",
  "email_scan": { "exposed": true, "breach_count": 186, "breaches": [...], "password_strength": [...], "risk": [{"risk_label":"Critical","risk_score":100}] } }

// Phone
{ "query": "+14155552671", "type": "phone",
  "phone_scan": { "valid": true, "country_code": "US", "country_name": "United States", "location": "California", "carrier": "AT&T", "line_type": "mobile" } }

// Username
{ "query": "johndoe", "type": "username",
  "username_scan": [{"site": "GitHub", "url": "https://github.com/johndoe"}, ...] }
```

**Required environment variables (from `.env.example`):**

| Variable | Used by | Required? |
|---|---|---|
| `NUMVERIFY_API_KEY` | `phone.py` — NumVerify via apilayer.net | Optional — without it returns `{"valid": false, "error": "API key not configured"}` |
| `THREATFOX_API_KEY` | `threatfox.py` — added to `Auth-Key` header | Optional — API still called without it at lower rate limit |
| `ipAPI_KEY` | `ipapi.py` — ip-api.com | Optional — free tier works without a key |

**Local media files (auto-downloaded on first request if missing):**
- `src/media/talos.txt` — Cisco Talos IP blocklist (`snort.org/downloads/ip-block-list`)
- `src/media/tor.txt` — Tor exit node IPs extracted from `check.torproject.org/exit-addresses` via regex

**Classifier routing:** The orchestrator routes to `"recon"` when:
- Input matches IPv4 regex (exact: `^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
- Input matches domain regex (exact: `^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$`)
- URL rule (`https://...`) must be matched by the **web** rule first, before the domain rule

**Output contract (after adapter):** `{ "analyzer": "recon", "pass": N, "input": str, "findings": [...], "risk_score": 0.0–10.0, "raw_output": str }`

**Full integration details:** See [docs/Recon-Analyzer-Orchestration.md](docs/Recon-Analyzer-Orchestration.md) for the adapter pattern, compose config, and classifier rules.

---

### 7. Web Vulnerability Analyzer

**Service location:** `backend/web-analyzer/`
**Docker service:** `web-analyzer` — runs at `http://web-analyzer:5005/api/web-analyzer/`
**Responsibility:**
- Analyzes URLs and web endpoints for vulnerabilities and security misconfigurations as an independent HTTP microservice.
- Performs: HTTP response analysis, security header auditing, technology fingerprinting, basic vuln scanning.
- Returns its own native JSON response; the Orchestrator's `web_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://web-analyzer:5005/api/web-analyzer/", json={"url": target_url})
```
**Output contract (after adapter):** `{ "analyzer": "web", "pass": N, "findings": [...], "risk_score": 0-10 }`

---

### 8. Findings Store

**File location:** `backend/orchestrator-ts/src/graph/state.ts` and `rawOutputStore.ts`
**Responsibility:**
- LangGraph state accumulates every adapter-normalized analyzer result across all passes.
- The run-scoped raw-output store retains bounded raw evidence for decision prompts and rule generation.
- The report stage receives the full findings history.

**Key behaviors:**
- Must preserve pass order and analyzer identity in every entry.
- Raw evidence is capped; the model receives references/summaries, not unbounded output.
- Reports are written under `REPORTS_DIR/<16-hex job id>/`.

---

### 9. Report Generator

**File location:** `backend/orchestrator-ts/src/report/` and `src/rules/`
**Responsibility:**
- Takes the findings summary and evidence references, generates optional narrative text with OpenRouter, and renders a PWNDoc-compatible JSON + self-contained HTML report.
- Generates YARA rules compiled by YARA-X and structurally validated SIGMA rules with evidence citations.
- Includes per-analyzer findings, overall risk score, recommendations, IOCs, and MITRE ATT&CK mappings.

**Key behaviors:**
- Pass structured findings/evidence to the model, not raw text blobs.
- Validate generated rules and report data against their Zod schemas before writing files.
- Never fabricate analyzer results; failures remain visible as findings/errors.

---

## Coding Conventions

### Language & Style
- **TypeScript/Node.js 20+** for the orchestrator (`backend/orchestrator-ts/`).
- **Python 3.11+ / Flask** for analyzer microservices only.
- **Docker + Docker Compose** for service orchestration.
- Orchestrator: strict TypeScript, Zod schemas, ESLint + Prettier, `npm run typecheck && npm run lint && npm test`.
- Analyzers: type hints, **black**, **ruff**; each has its own `Dockerfile` and `requirements.txt`.

### Analyzer Output Contract
Every adapter produces the SecFlow contract:
```ts
{
  analyzer: "malware" | "steg" | "recon" | "web" | "macro",
  pass: number,              // loop iteration number (1-indexed)
  input: string,             // what was passed to this analyzer
  findings: Finding[],       // list of individual finding objects
  risk_score: number,        // 0.0 – 10.0
  raw_output: string         // bounded raw evidence for decisions/reporting
}
```

### AI Decision Engine Contract
The model decision is a validated structured object:
```ts
{
  action: "analyze_malware" | "analyze_steg" | "analyze_recon" |
          "analyze_web" | "analyze_macro" | "generate_yara" |
          "generate_sigma" | "generate_report" | "finish",
  targetId: string | null,   // required for analyzer actions; null for finish
  reasoning: string          // explanation of the decision (1–2000 chars)
}
```

### Error Handling
- Analyzer failures must never crash the whole pipeline. Record a structured tool error/finding and continue when other evidence exists.
- The orchestrator must log all loop decisions (run id, pass, tool, target id, reasoning, duration) for audit.
- Do not fabricate analyzer output; if a run produces no findings, return the documented 500 error.

### File Naming
```
backend/
  orchestrator-ts/                 ← TypeScript + LangGraph orchestrator (port 5000)
    src/
      index.ts                     ← Express bootstrap
      app.ts                       ← App factory + middleware
      config.ts                    ← Zod environment config
      routes/                      ← smart-analyze, health, reports
      classifier/                  ← magic-byte + string classification rules
      graph/                       ← LangGraph state, decision, loop, finalize
      analyzers/                   ← HTTP clients, adapters, validated tools
      pipeline/                    ← runner, uploads, payload downloader
      security/                    ← SSRF/network guard
      rules/                       ← YARA-X + SIGMA generation/validation
      report/                      ← PWNDoc JSON/HTML + narrative
      prompts/                     ← centralized evidence-isolated prompts
      model/                       ← OpenRouter provider + model adapter
    tests/                         ← unit, contract, parity, live-gated tests
    Dockerfile
    package.json
  Malware-Analyzer/                ← Analyzer (port 5001)
  Steg-Analyzer/                   ← Analyzer (port 5002)
  Recon-Analyzer/                  ← Analyzer (port 5003)
  Web-Analyzer/                    ← Analyzer (port 5005)
  macro-analyzer/                  ← Analyzer (port 5006)
  compose.yml                      ← All services on secflow-net
  .env.example
```

---

## What NOT to Do

- Do not call the AI Decision Engine on the first pass when a deterministic classifier rule matches.
- Do not skip accumulating a pass result in graph state after any analyzer call.
- Do not generate a report unless the loop has completed (max passes, `finish`, or a configured limit).
- Do not hardcode the OpenRouter API key — use `OPENROUTER_API_KEY`.
- Do not import analyzer code into the orchestrator — always call analyzers via HTTP using their service URLs.
- Do not modify analyzer service code to fit the SecFlow contract — update the adapters in `orchestrator-ts/src/analyzers/adapters/`.
- Do not remove or rewrite Python analyzer services or their dependencies.
- Do not allow model output to choose arbitrary URLs, files, commands, or analyzer endpoints; analyzer tools accept only trusted `targetId` values.
- Do not implement frontend features until explicitly instructed.

---

## References

- [ProjectDetails.md](ProjectDetails.md) — Full project specification
- [docs/migration.md](docs/migration.md) — Integration guide: analyzer services setup
- [docs/architecture.md](docs/architecture.md) — System architecture diagram (microservices)
- [docs/pipeline-flow.md](docs/pipeline-flow.md) — Pipeline loop logic
- [docs/analyzers.md](docs/analyzers.md) — Per-analyzer capability spec
- [docs/implementation-guide.md](docs/implementation-guide.md) — Hands-on implementation guide with code snippets
- [docs/Malware-Analyzer-Orchestration.md](docs/Malware-Analyzer-Orchestration.md) — Malware Analyzer integration details (real endpoints, adapter, compose config)
- [docs/Recon-Analyzer-Orchestration.md](docs/Recon-Analyzer-Orchestration.md) — Recon Analyzer integration details (real endpoints, adapter, compose config)
- [docs/ts-migration/](docs/ts-migration/) — TypeScript/LangGraph migration record, parity results, and documented deviations
