# Step 1 — Baseline and contracts

**Status:** complete
**Source of truth:** the code in `backend/orchestrator/`, `backend/compose.yml`, the analyzer services' routes, and `frontend/src/`. Where `AGENTS.md` disagrees with the code, this document records the **code** and flags the discrepancy.

> This document describes the system **before** the migration. It is the reference for every TypeScript port and for parity validation in Step 11.

---

## 1. What actually runs today

```
Browser (Vite/React)
   │  POST /api/smart-analyze?passes=3      (multipart "file"  |  JSON {target|url|query})
   ▼
Python Flask orchestrator  (backend/orchestrator, container port 5000, host 5000)
   │  1. deterministic classifier (python-magic + `file` output + regex rules)
   │  2. analyzer HTTP call  →  adapter  →  SecFlow contract
   │  3. Groq (OpenAI-compatible) routing decision  →  next analyzer/target or stop
   │  4. repeat up to `passes` (3/4/5), plus opportunistic payload download
   │  5. report generation (base report + Groq summary/recs + 3 Groq threat-intel calls)
   ▼
GET /api/report/<job_id>/json  |  /html       written under /app/reports/<job_id>/
```

There is **one** orchestrator loop. There is no LangGraph/TS layer yet.

### Important discrepancies with `AGENTS.md`

| Topic | `AGENTS.md` says | Code actually does |
|---|---|---|
| LLM provider | Gemini | **Groq** via the OpenAI SDK (`base_url=https://api.groq.com/openai/v1`). No Gemini call exists in the orchestrator. |
| Routing model | (Gemini) | `qwen/qwen3-32b` for routing (`engine.py`) and report enhancement (`report_generator.py`); `llama-3.3-70b-versatile` for threat intel (`threat_intel.py`). |
| Env var | `GEMINI_API_KEY` | Orchestrator requires **`GROQ_API_KEY`**. `GEMINI_API_KEY` is only consumed by the *web* and *malware* analyzer containers (`ai-summary`, `diagram-generator`, web `/ai-analyze`). |
| Recon `/scan` | response has no VirusTotal | Recon adapter **also** handles a `virustotal` key (present when `VIRUSTOTAL_API_KEY` is set in the recon container). |
| Analyzer count | 4–5 | 5 analyzers are wired: `malware`, `steg`, `recon`, `web`, `macro`. |
| "Ghat/chat prompt" | referenced | **No Ghat/chat prompt or chat endpoint exists anywhere in the repository.** Only the prompts listed in §7 exist. |

---

## 2. Entry points (frontend-facing contract)

`backend/orchestrator/app/routes.py`

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/health` | — | `{"status":"healthy","service":"secflow-orchestrator"}` |
| POST | `/api/smart-analyze?passes=N` | multipart `file` **or** JSON body with `target` / `url` / `query` | see below |
| GET | `/api/report/<job_id>/<fmt>` | `fmt ∈ {json,html}` | file download (`json` as attachment) |

`passes` handling: `int()`; **non-numeric silently falls back to 3**; numeric values outside `{3,4,5}` → HTTP 400 `{"error":"passes must be 3, 4, or 5"}`.

`smart-analyze` response (HTTP 200):

```json
{
  "job_id": "<sha256(user_input)[:16]>",
  "passes_completed": 3,
  "overall_risk_score": 9.5,
  "findings_summary": [ /* serialized FindingsStore: one contract dict per pass */ ],
  "report_paths": {"json": "/app/reports/<id>/report.json", "html": "/app/reports/<id>/report.html"},
  "report_urls":  {"json": "/api/report/<id>/json", "html": "/api/report/<id>/html"}
}
```

Errors: 400 for bad `passes` / missing input / unknown report format / invalid `job_id`; 404 for missing report; 500 for save failure, empty store, or any uncaught pipeline exception (`{"error": "..."}`).
The upload is written to a `NamedTemporaryFile` and deleted in `finally`. `job_id` is derived from the **temp path**, so upload job IDs are per-request and not stable for the same file.

Frontend consumption (`frontend/src/pages/dashboard/SmartPipelinePage.jsx`): only `job_id`, `findings_summary[].analyzer|pass|findings|risk_score`, `overall_risk_score`, `report_urls`. `report_urls` are resolved to absolute with the orchestrator origin (`frontend/src/config/api.js`).

`report_paths` are **container-local** paths (`/app/reports/...`); only `report_urls` are usable by clients.

---

## 3. Input types and deterministic classification

`backend/orchestrator/app/classifier/{classifier,rules}.py`. `classify()` returns `(analyzer | None, mime_type, magic_output)`. File inputs use `python-magic` (`from_file(..., mime=True)` and `from_file(...)`); non-files use `mime_type="text/plain"`, `magic_output=raw_input`.

Rules are evaluated in order; first match wins:

| # | Condition | Analyzer |
|---|---|---|
| 1 | `mime` starts with `image/` **or** magic contains `PNG/JPEG/GIF/BMP/TIFF/WEBP` | `steg` |
| 2 | Office/RTF MIME set, or magic contains `Composite Document File V2 / Microsoft Office|Word|Excel|PowerPoint / Office Open XML / Rich Text Format`, or (`application/zip` and the raw input ends with `.docx/.xlsx/.pptx/.xlsm/.docm/.pptm/.xlsb`) | `macro` |
| 3 | executable MIME set (`application/x-executable|x-dosexec|x-msdos-program|x-elf|vnd.microsoft.portable-executable|octet-stream`) **and** magic contains `PE32/ELF/Mach-O/MS-DOS/MS Windows` | `malware` |
| 4 | magic contains `PE32/ELF/Mach-O/MS-DOS executable` (regardless of MIME) | `malware` |
| 5 | `^https?://` (case-insensitive) | `web` |
| 6 | IPv4 regex `^((25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\.){3}(25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)$` | `recon` |
| 7 | domain regex `^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$` | `recon` |
| — | no match | `None` → AI fallback classification |

**Rule 5 must stay before 6/7** so a URL is never treated as a domain.

Unknown-type fallback: `get_file_head()` runs `head -100 <path>`; a synthetic `analyzer:"classifier", pass:0` pseudo-result is passed to the AI router, and `next_tool` becomes the first analyzer. **No AI is called on pass 1 when a deterministic rule matches.**

Consequence: a bare email/phone/username is **not** matched by the classifier (no rule), so it reaches the AI fallback, which can only return one of the five analyzers — in practice `recon` → `/footprint`.

---

## 4. Analyzer endpoints (unchanged by this migration)

All calls are `requests` over the internal `secflow-net` Docker network. Base URLs come from env (see §8).

### 4.1 Malware — `MALWARE_ANALYZER_URL` (`http://malware-analyzer:5000/api/malware-analyzer`)

Two sequential calls, **merged** into `{"vt": ..., "decompile": ...}`:

| Call | Method/Path | Body | Timeout | Failure behaviour |
|---|---|---|---|---|
| 1 | POST `/file-analysis` | multipart `file` | 60 s | captured as `{"success": false, "error": ...}`; never raises |
| 2 | POST `/decompile` | multipart `file` | 180 s | same |

Extension allowlist (service-side): `exe dll so elf bin o out`; max 50 MB. Response shapes used: `vt.success`, `vt.filename`, `vt.report.data.attributes.stats|results`; `decompile.success|filename|decompiled|objdump`.
Health: GET `/health`.

### 4.2 Steg — `STEG_ANALYZER_URL` (`http://steg-analyzer:5000/api/steg-analyzer`)

Asynchronous, three steps:

1. POST `/upload`, multipart field **`image`** (30 s) → `{"submission_hash": "..."}`
2. Poll GET `/status/<hash>` every **3 s**, max **300 s** (10 s per request) → `status ∈ {queued,running,completed,error,...}`
3. GET `/result/<hash>` (30 s) → `{"results": {tool: {status, output, note, download, error}}}`

Any failure/timeout → `adapt({})` (empty result, risk 0). The upload is `MAX_CONTENT_LENGTH=3145728` (3 MB) at the service.

### 4.3 Recon — `RECON_ANALYZER_URL` (`http://recon-analyzer:5000/api/Recon-Analyzer`)

Endpoint is chosen from the query, not from the classifier:

- IP or domain → POST `/scan` `{"query": ...}`
- anything else → POST `/footprint` `{"query": ...}`

Timeout 60 s. Failure → `adapt({})`. Response keys consumed: `ipapi.ip_info[]`, `talos.blacklisted`, `tor.is_tor_exit`, `tranco.found|rank`, `threatfox.found|malware|confidence_level`, optional `virustotal`, and for footprint `type` + `email_scan` / `phone_scan` / `username_scan`.

### 4.4 Web — `WEB_ANALYZER_URL` (`http://web-analyzer:5000/api/web-analyzer`)

No aggregate endpoint. The orchestrator calls **12 GET routes in sequence** with `?url=`:

| key | route | timeout |
|---|---|---|
| status | `/status` | 15 s |
| security_headers | `/security-headers` | 20 s |
| tls | `/tls` | 20 s |
| ssl | `/ssl` | 20 s |
| hsts | `/hsts` | 15 s |
| firewall | `/firewall` | 20 s |
| redirects | `/redirects` | 20 s |
| headers | `/headers` | 15 s |
| redirect_chain | `/redirect-chain` | 30 s |
| malware_check | `/malware-check` | 30 s |
| url_parse | `/url-parse` | 10 s |
| dns | `/dns` | 15 s |

Only HTTP 200 responses are aggregated; every error is logged and skipped. **Worst case serial time ≈ 245 s.**

### 4.5 Macro — `MACRO_ANALYZER_URL` (`http://macro-analyzer:5000/api/macro-analyzer`)

POST `/analyze`, multipart `file`, timeout 60 s. Extension allowlist: `doc docx xls xlsx xlsm xlsb ppt pptx pptm rtf docm`. Response keys consumed: `risk_level, has_macros, macro_count, file_type, filename, flags, indicators, iocs, macros, xlm_macros, vt`.

### 4.6 URL analyzer

`url_adapter.py` is a **placeholder**; no url-analyzer service exists in `compose.yml` (merged into web-analyzer). Do not expose a URL tool.

---

## 5. Normalization contracts (adapters)

Every adapter returns exactly:

```ts
{ analyzer: "malware"|"steg"|"recon"|"web"|"macro"|"url",
  pass: number, input: string,
  findings: {type: string, detail: string, severity: "critical"|"high"|"medium"|"low"|"info", evidence?: string, extracted_path?: string|null}[],
  risk_score: number /* 0–10, rounded 2dp */,
  raw_output: string /* consumed by the AI router */ }
```

`steg` additionally returns `extracted_files: string[]`.

Risk scoring: `sum(severity weight)` capped at 10 for malware/steg/recon/web where critical=4.0, high=2.5, medium=1.0, low=0.3, info=0.0. **Macro is different**: a fixed `risk_level` map (`malicious 9.5, suspicious 6.5, macro_present 3.0, clean 0.5`) raised to ≥9.5/≥7.0 by VT detections.

Fixture-backed expectations live in `backend/orchestrator/tests/test_adapters.py` and use `docs/ts-migration/fixtures/`.

---

## 6. Decision loop (the part being replaced)

`run_pipeline()` in `orchestrator.py` + `decide_next()` in `ai/engine.py`.

1. **Pass 1** is the deterministic classifier (or AI fallback when unknown).
2. After each pass: append to `FindingsStore`, then call the router **unless** this was the last pass.
3. Router (`decide_next`):
   - Extracts artifacts from the **full** `raw_output` + C-string stitching + findings evidence: URLs ≤10, IPs ≤5, domains ≤10 (`_DOMAIN_NOISE` filters gnu.org/github.com/localhost/example.com/…).
   - **Hard pre-check:** if no URLs/IPs/domains → return `next_tool: null` *without calling the model*.
   - Otherwise builds a SOC-analyst prompt (stop/continue conditions + 6 ordered decision rules) and calls Groq `qwen/qwen3-32b`, `temperature 0.1`, `max_tokens 512`, system message `"/no_think"`.
   - Strips ` thinking` blocks and markdown fences, then `json.loads`. Returns `{next_tool, target, reasoning}`.
   - Any error / empty response / bad JSON → `_rule_based_decide()` fallback (deterministic equivalent rules).
   - `_sanitize_target()` forces bare host for `recon` and `http(s)://` URL for `web`; rejects `.in`-style fragments. Missing target → `_fallback_target()` from artifacts, else the previous input.
4. Duplicate `(tool, input)` pairs are refused and **terminate** the loop.
5. Before honouring a `next_tool: null`, the orchestrator tries to **download a payload** from URLs in the last pass: known payload extensions first; `text/html|plain|css|js|json` skipped; 50 MB cap; content-type → extension → magic to pick `malware`/`macro`/`steg`; injects a `payload_downloaded` (severity `high`) finding with the source URL.
6. `_normalize_target()` last-mile normalizes `recon` to a bare host and `web` to `http(s)://…`.
7. For file tools, a non-existent relative target is replaced by the current input.
8. Temp downloads are deleted at the end.

Termination reasons: max passes, model null + no downloadable payload, duplicate pair, invalid/unknown tool, failed target normalization.

**Errors never crash the pipeline**: an analyzer exception becomes a single `{"type":"error","severity":"low"}` finding with `risk_score: 0`.

---

## 7. Prompts and model configuration (current)

| # | Location | Purpose | Model / params |
|---|---|---|---|
| P1 | `app/ai/engine.py::_build_prompt` | Routing decision (SOC analyst, stop/continue conditions, JSON out) | Groq `qwen/qwen3-32b`, temp 0.1, max 512 |
| P2 | `app/reporter/report_generator.py::_ask_groq_to_enhance` | Executive summary + recommendations | Groq `qwen/qwen3-32b`, temp 0.2, max 1024 |
| P3 | `app/ai/threat_intel.py::_call_threat_summary` | Threat summary (name, actor, chain, IOCs, MITRE, confidence) | Groq `llama-3.3-70b-versatile`, temp 0.1, max 2048 |
| P4 | `app/ai/threat_intel.py::_call_yara_rules` | 2–5 YARA rules with reasoning | same, temp 0.1, max 3072 |
| P5 | `app/ai/threat_intel.py::_call_sigma_rules` | 2–4 SIGMA rules with reasoning | same, temp 0.1, max 3072 |
| P6 | `app/ai/keywords.txt` | Keyword list for excerpting long raw output | data file |

Shared context handling: excerpt capped at **3000 chars** for routing (keyword lines first, else head); threat intel context capped at **16 000 chars** keeping the **last** portion; decompilation/disassembly evidence capped at **1000 lines**.

**No "Ghat/chat" system prompt, chat endpoint, or conversational agent exists in this repository.** The only prompts are P1–P5. The migration must port P1–P5 semantics; there is nothing else to "review".

---

## 8. Configuration inventory

`backend/compose.yml` orchestrator service passes: `GROQ_API_KEY`, `MALWARE_ANALYZER_URL`, `STEG_ANALYZER_URL`, `RECON_ANALYZER_URL`, `WEB_ANALYZER_URL`, `MACRO_ANALYZER_URL`, `MAX_PASSES`, `PYTHONUNBUFFERED`; mounts `./reports:/app/reports`.

`backend/orchestrator/.env.example` is **stale**: it documents `GEMINI_API_KEY`, omits `GROQ_API_KEY` and `MACRO_ANALYZER_URL`. Do not copy it as-is.

`MAX_PASSES` is declared in compose but never read — the route's `passes` query parameter (default 3) is what actually bounds the loop.

---

## 9. Report generation

`generate_report(findings_json, job_id, output_dir, base_name)`:

1. `_build_base_report()` — deterministic: `input = findings[0].input`, `total_passes`, `overall_risk_score = max(pass risk)`, `passes[{pass_number, analyzer, findings}]`, `summary="Automated analysis completed."`, `recommendations=[]`.
2. `_ask_groq_to_enhance()` — compact findings (type/detail/severity only) → summary 2–3 sentences + recommendations. Failure is swallowed (defaults kept).
3. JSON-Schema validation via `pwndoc_schema.json` — **informational only** (warnings, never fatal).
4. `generate_threat_intel()` — three sequential Groq calls: threat summary → YARA → SIGMA. Each failure is caught and replaced with an empty structure; `threat_intel.error` records it. Added as `report_data.threat_intel`.
5. Writes `report.json` (full evidence + threat intel) and `report.html` (bespoke HTML renderer, evidence-type aware, no Jinja).

Report contract: `docs/ts-migration/fixtures/report.json`; schema: `backend/orchestrator/app/reporter/pwndoc_schema.json`.

There is **no YARA syntax validator and no SIGMA validator** today; rule text is model output and is rendered verbatim.

---

## 10. Docker layout

| Service | Container→host port | Health |
|---|---|---|
| orchestrator | 5000→5000 | `/api/health` (curl) |
| malware-analyzer | 5000→5001 | `/api/malware-analyzer/health`, 4 GB memory |
| steg-analyzer (+worker/redis/postgres/initdb) | 5000→5002 | none |
| recon-analyzer | 5000→5003 | `/api/Recon-Analyzer/health` |
| web-analyzer | 5000→5005 | `/api/web-analyzer/health` |
| macro-analyzer | 5000→5006 | `/api/macro-analyzer/health` |

Shared bridge network `secflow-net`. Orchestrator depends on analyzer health/start conditions; only `./reports` is mounted.

---

## 11. Test baseline

New baseline suite: `backend/orchestrator/tests/` (pytest).

| File | Covers |
|---|---|
| `test_classifier_rules.py` | rule order, URL-before-domain, all five analyzer routes, unknown→AI fallback |
| `test_adapters.py` | all adapters against fixtures, severity/risk invariants, error paths |
| `test_findings_store.py` | append order, identity, JSON round-trip |
| `test_report_contract.py` | base report + sample report validate against `pwndoc_schema.json` |
| `test_api_contract.py` | health, smart-analyze success/errors, report 400/404 semantics |

Run:
```bash
cd backend/orchestrator && ../../.venv/bin/pytest     # 52 passed
```
Host note: `python-magic` needs libmagic; `tests/conftest.py` installs a deterministic stub when libmagic is absent (real MIME sniffing is only exercised in Docker).

Fixtures: `docs/ts-migration/fixtures/` — `malware-file-analysis{,-clean}.json`, `malware-decompile.json`, `steg-result.json`, `recon-scan.json`, `recon-footprint-email.json`, `macro-analyze.json`, `web-aggregated.json`, `smart-analyze-response.json`, `report.json`. All secrets and personal data redacted.

---

## 12. Migration checklist derived from the real repo

**Contracts to preserve**
- [x] `POST /api/smart-analyze?passes=3|4|5` — multipart `file` or JSON `target|url|query`; same response keys.
- [x] `GET /api/health`; add `GET /api/ready` without breaking the old one.
- [x] `GET /api/report/<job_id>/<json|html>` with hex-only `job_id` sanitisation and 400/404 semantics.
- [x] SecFlow contract dicts in `findings_summary` (field names and severity vocabulary).
- [x] PWNDoc report fields: `input, total_passes, overall_risk_score, summary, passes[], recommendations[], threat_intel{model,error,threat_summary,yara,sigma}`.
- [x] Risk semantics per adapter (including the macro fixed map).
- [x] Pass numbering starts at 1 and preserves analyzer identity/order.

**Tools to build (one per analyzer, no url tool)**
- [x] `malware` → `/file-analysis` + `/decompile`, 60 s / 180 s, merged.
- [x] `steg` → upload/poll/result with `image` field, 3 s interval, 300 s budget.
- [x] `recon` → `/scan` vs `/footprint` selection, `{"query": ...}`, 60 s.
- [x] `web` → 12 sequential GET routes with per-route timeouts.
- [x] `macro` → `/analyze`, 60 s.
- [x] yara / sigma / report as separate stages with evidence gates.

**Model layer**
- [x] Replace Groq with OpenRouter via `@openrouter/ai-sdk-provider`; central provider module; `OPENROUTER_API_KEY` / `OPENROUTER_MODEL`.
- [x] Port P1–P5 semantics (no Ghat prompt exists).
- [x] Structured decision output (enumerated tool + validated args), not free-form JSON parsing.
- [x] Deterministic fallback when the model fails, as today.

**Behaviour to keep**
- [x] No AI on pass 1 when a deterministic rule matches.
- [x] Artifact extraction + no-artifact early stop.
- [x] Duplicate `(tool,target)` prevention.
- [x] Opportunistic payload download with provenance finding (and SSRF guard — new, Step 10).
- [x] Analyzer failures produce low-severity `error` findings, never exceptions.

**New requirements from the spec (not present today)**
- [x] Zod schemas for every tool input/output.
- [x] YARA/SIGMA syntax validation where a validator is available.
- [x] SSRF protections for URL/domain/IP analysis and payload downloads.
- [x] Per-run IDs, structured redacted logs, cycle/timeout budgets.
- [x] Full test coverage for limits, malformed model output, injection in analyzer output.

**Removal gate**
- [x] Only after parity: delete `backend/orchestrator/` Python service and Gemini/Groq-specific deps; keep all analyzer services.
