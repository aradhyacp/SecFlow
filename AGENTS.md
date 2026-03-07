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

**Service location:** `backend/recon-analyzer/`
**Docker service:** `recon-analyzer` — runs at `http://recon-analyzer:5003/api/recon-analyzer/`
**Responsibility:**
- Performs OSINT and infrastructure reconnaissance on IPs, domains, and hostnames as an independent HTTP microservice.
- Collects: WHOIS data, DNS records, open ports, geolocation, ASN, reverse DNS, threat intel lookups.
- Returns its own native JSON response; the Orchestrator's `recon_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://recon-analyzer:5003/api/recon-analyzer/", json={"target": ip_or_domain})
```
**Output contract (after adapter):** `{ "analyzer": "recon", "pass": N, "findings": [...], "risk_score": 0-10 }`

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
  malware-analyzer/                  ← Analyzer microservice (Docker service, port 5001)
  steg-analyzer/                     ← Analyzer microservice (Docker service, port 5002)
  recon-analyzer/                    ← Analyzer microservice (Docker service, port 5003)
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
- [docs/Malware-Analyzer-Orchestration.md](docs/Malware-Analyzer-Orchestration.md) — Real Malware Analyzer integration guide (based on actual source)
