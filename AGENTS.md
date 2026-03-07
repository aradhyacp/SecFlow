# AGENTS.md — SecFlow

This file defines the agent architecture for SecFlow and provides instructions for AI coding assistants (GitHub Copilot, etc.) working in this repository.

---

## Project Context

**SecFlow** is a Python-based automated threat analysis pipeline. Its core is a loop-driven orchestrator that routes any input (file, URL, IP, domain, image) through specialized analyzers, guided by Gemini AI tool-calling, and produces PWNDoc reports.

The backend is the primary focus. The frontend is not yet under development.

---

## Agent Roles

SecFlow's runtime pipeline is composed of the following agents/workers:

---

### 1. Pipeline Orchestrator

**File location:** `backend/orchestrator/`
**Responsibility:**
- Receives the user's input and hands it to the Input Classifier for the first pass.
- After each analyzer pass, receives the analyzer output and routes it to the AI Decision Engine.
- Maintains loop state: current pass count, max passes, termination flags.
- Writes every pass's output to the Findings Store.
- Triggers Report Generation when the loop ends.

**Key behaviors:**
- Loop runs for a user-configured max (3, 4, or 5 passes).
- Terminates early if the AI Decision Engine signals no further analyzers are relevant.
- Must never call AI on the first pass if a deterministic rule applies.

---

### 2. Input Classifier

**File location:** `backend/classifier/`
**Responsibility:**
- Identifies the type of the user's input using the `file` system command and `python-magic`.
- Applies deterministic routing rules to select the first analyzer:
  - Image (PNG, JPG, BMP, GIF…) → Steganography Analyzer
  - Executable / PE / binary → Malware Analyzer
  - URL string → Web Vulnerability Analyzer
  - IP address / domain → Reconnaissance Analyzer
- Fallback: if file type is ambiguous or unknown, passes `file`/`python-magic` output + first 100 lines of the file to the AI Decision Engine for classification.

**Key behaviors:**
- No AI is invoked on the first pass when a deterministic rule matches.
- For unknown types, always include `head -100` of the input alongside `file`/`python-magic` output when calling AI.

---

### 3. AI Decision Engine

**File location:** `backend/ai/`
**Responsibility:**
- Wraps the Gemini API with tool-calling capability.
- Takes analyzer output (or classifier output for unknown types) and returns the name of the next analyzer to call (or a termination signal).
- Implements the keyword-grep fallback:
  - If Gemini's response lacks confidence → pass the full analyzer output.
  - If output is noisy → grep a predefined keyword list; pass matched snippets to Gemini.

**Key behaviors:**
- Must return a structured response containing: `next_tool` (string | null) and `reasoning` (string).
- `next_tool: null` = the loop should terminate.
- Keyword list for fallback grep is maintained in `backend/ai/keywords.txt`.

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

**File location:** `backend/store/`
**Responsibility:**
- Persistent in-memory (and optionally on-disk) accumulator for all analyzer outputs across all loop passes.
- Appends new findings after every pass.
- Provides the full findings history to the Report Generator.

**Key behaviors:**
- Must preserve pass order and analyzer identity in every entry.
- Should expose a method to serialize findings to JSON for the report generator.

---

### 9. Report Generator

**File location:** `backend/reporter/`
**Responsibility:**
- Takes the full Findings Store contents and passes them to Gemini AI for formatting.
- Produces a PWNDoc-compatible report in three formats: JSON, PDF, HTML.
- The report includes: threat summary per analyzer, overall risk score, actionable recommendations, findings timeline.

**Key behaviors:**
- Pass the complete findings store as structured JSON to Gemini, not raw text.
- Validate the Gemini-formatted output against the PWNDoc schema before writing to file.

---

## Coding Conventions

### Language & Style
- **Python 3.11+** for all backend code.
- **Flask** for all HTTP service entrypoints.
- **Docker + Docker Compose** for service orchestration.
- Use **type hints** on all function signatures.
- Format with **black** and lint with **ruff**.
- Each analyzer service is its own Docker container with its own `Dockerfile` and `requirements.txt`.

### Analyzer Output Contract
Every analyzer must return a dict conforming to:
```python
{
    "analyzer": str,          # e.g. "malware", "steg", "recon", "web"
    "pass": int,              # loop iteration number (1-indexed)
    "input": str,             # what was passed to this analyzer
    "findings": list[dict],   # list of individual finding objects
    "risk_score": float,      # 0.0 – 10.0
    "raw_output": str         # raw tool/command output (for AI consumption)
}
```

### AI Decision Engine Contract
The AI Decision Engine must return:
```python
{
    "next_tool": str | None,  # "malware" | "steg" | "recon" | "web" | None
    "reasoning": str          # explanation of the decision
}
```

### Error Handling
- Analyzers must never crash the pipeline. Wrap tool calls in try/except and return an error entry in `findings` instead.
- The Orchestrator must log all loop decisions (pass number, tool chosen, reasoning) for audit.

### File Naming
```
backend/
  orchestrator/                    ← NEW Docker service (port 5000)
    app/
      __init__.py
      routes.py                      ← Flask: POST /api/smart-analyze
      orchestrator.py                ← Pipeline loop (calls analyzers via HTTP)
      classifier/
        classifier.py
        rules.py
      ai/
        engine.py
        keywords.txt
      adapters/                      ← Translate analyzer responses → SecFlow contract
        malware_adapter.py
        steg_adapter.py
        recon_adapter.py
        url_adapter.py
        web_adapter.py
      store/
        findings_store.py
      reporter/
        report_generator.py
        pwndoc_schema.json
    Dockerfile
    requirements.txt
    .env.example
  Malware-Analyzer/                  ← REAL SOURCE (Docker service, host port 5001, container port 5000)
  steg-analyzer/                     ← Analyzer microservice (Docker service, port 5002)
  Recon-Analyzer/                    ← REAL SOURCE (Docker service, host port 5003, container port 5000)
  url-analyzer/                      ← Analyzer microservice (Docker service, port 5004, internal)
  web-analyzer/                      ← Analyzer microservice (Docker service, port 5005)
  compose.yml                        ← Includes all 6 services
  .env.example
```

---

## What NOT to Do

- Do not call the AI Decision Engine on the first pass when a deterministic classifier rule matches.
- Do not skip writing to the Findings Store after any pass.
- Do not generate a report unless the loop has completed (either max passes or early termination).
- Do not hardcode the Gemini API key — use environment variables (`GEMINI_API_KEY`).
- Do not import analyzer code directly into the orchestrator — always call analyzers via HTTP using their service URLs.
- Do not modify analyzer service code to fit the SecFlow contract — use adapters in `orchestrator/app/adapters/` to translate responses.
- Do not expose the `url-analyzer` as a public API route — it is an internal service called only by the Orchestrator.
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
