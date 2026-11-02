# SecFlow — System Architecture

SecFlow runs one **TypeScript/Node.js orchestrator** built on a single
**LangGraph.js** state graph, plus five independent **Python analyzer
microservices**. The analyzers keep their own REST APIs and are called over the
Docker network; there is no direct code import between the orchestrator and the
analyzers.

---

## High-Level Component Diagram

```
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │                     SecFlow — Docker Compose Network                         │
 │                                                                              │
 │  ┌─────────────┐   POST /api/smart-analyze                                  │
 │  │  User /     │──────────────────────────────────────────────────────┐     │
 │  │  Frontend   │                                                      ▼     │
 │  └─────────────┘                                                      │     │
 │                              ┌──────────────────────────────────────────┐   │
 │                              │  orchestrator-ts (port 5000)             │   │
 │                              │  Express + LangGraph.js + OpenRouter     │   │
 │                              │                                          │   │
 │                              │  ┌──────────────────────────────────┐   │   │
 │                              │  │  Classifier (magic bytes/rules)  │   │   │
 │                              │  └──────────────┬───────────────────┘   │   │
 │                              │                 │ deterministic first   │   │
 │                              │  ┌──────────────▼───────────────────┐   │   │
 │                              │  │  Analysis graph                  │   │   │
 │                              │  │  decision → tool → decision ...  │   │   │
 │                              │  └──────┬───────────────┬───────────┘   │   │
 │                              │         │ HTTP          │ finish         │   │
 │                              │  ┌──────▼──────┐  ┌─────▼───────────┐   │   │
 │                              │  │ Analyzer    │  │ YARA-X / SIGMA  │   │   │
 │                              │  │ tool layer  │  │ report stage    │   │   │
 │                              │  └──────┬──────┘  └─────────────────┘   │   │
 │                              └─────────┼─────────────────────────────────┘   │
 │                                        │                                     │
 │              ┌─────────────────────────┴────────────────────────────┐        │
 │              │          Analyzer Services (Docker network)          │        │
 │    ┌─────────▼────────┐  ┌──────────────────┐  ┌─────────────▼──────┐ │        │
 │    │ malware-analyzer │  │  steg-analyzer   │  │   recon-analyzer   │ │        │
 │    │   port 5001      │  │   port 5002      │  │     port 5003      │ │        │
 │    └──────────────────┘  └──────────────────┘  └────────────────────┘ │        │
 │    ┌──────────────────┐  ┌──────────────────┐                         │        │
 │    │   web-analyzer   │  │  macro-analyzer  │                         │        │
 │    │   port 5005      │  │   port 5006      │                         │        │
 │    └──────────────────┘  └──────────────────┘                         │        │
 │              └────────────────────────────────────────────────────────┘        │
 └──────────────────────────────────────────────────────────────────────────────┘
```

The steg service also brings its own PostgreSQL, Redis, initialiser, and RQ
worker containers. Those are implementation details of that analyzer and are not
part of the orchestrator contract.

---

## Components

### Orchestrator (`backend/orchestrator-ts/`)

- **Entry point:** `src/index.ts`, Express on port `5000`.
- **API:** `POST /api/smart-analyze`, `GET /api/health`, `GET /api/ready`,
  `GET /api/report/:jobId/:fmt`.
- **Graph:** `src/graph/analysis.ts` builds the LangGraph state machine.
  `src/graph/finalize.ts` runs YARA, SIGMA, and the report stage after the loop.
- **Model access:** `src/model/` wraps OpenRouter through the Vercel AI SDK.
  The model chooses from a schema-validated action list; it cannot supply
  arbitrary URLs, paths, or commands.
- **Runner:** `src/pipeline/index.ts` creates run-scoped tools/loggers, hashes
  the input for the stable job id, enforces the total deadline, cleans up
  temporary files, and maps errors to HTTP responses.

### Input Classifier (`src/classifier/`)

- File input is identified from magic bytes (`sniff.ts`), MIME hints, and
  extension (`rules.ts`).
- String input uses the existing URL, IPv4, domain, email, and phone regexes.
- URL is checked before domain, so `https://example.com` routes to web analysis.
- Deterministic matches avoid a model call on pass 1. Unknown input exposes the
  appropriate tools and includes a bounded, untrusted file-head preview.

### Analyzer Adapters and Tools (`src/analyzers/`)

Each analyzer has:

- a typed HTTP client with timeouts, bounded responses, and retries;
- an adapter that normalises the native response into the SecFlow contract;
- a validated tool (`analyze_malware`, etc.) that accepts only a trusted
  `targetId`.

Native analyzer endpoints are unchanged:

| Analyzer | Internal base URL | Request |
|---|---|---|
| malware | `http://malware-analyzer:5000/api/malware-analyzer` | multipart; `/decompile` + `/file-analysis` |
| steg | `http://steg-analyzer:5000/api/steg-analyzer` | multipart; async upload/poll |
| recon | `http://recon-analyzer:5000/api/Recon-Analyzer` | JSON `{"query": "..."}` |
| web | `http://web-analyzer:5000/api/web-analyzer` | JSON `{"url": "..."}` |
| macro | `http://macro-analyzer:5000/api/macro-analyzer` | multipart; `/analyze` |

### Findings State and Evidence

- `src/graph/state.ts` holds the validated graph state: targets, findings,
  counters, tool history, errors, rules, and report state.
- `src/graph/rawOutputStore.ts` stores bounded raw evidence. The model receives
  references and excerpts, not unbounded decompiler/VT dumps or sample bytes.
- Every analyzer result preserves pass order and analyzer identity.

### Rules and Report Stages (`src/rules/`, `src/report/`)

- YARA rules are requested with evidence citations, then **compiled with
  YARA-X WASM** before being accepted.
- SIGMA rules are schema-checked and structurally validated.
- The report stage emits PWNDoc-compatible JSON and a self-contained HTML
  report with an export-to-PDF button. Optional narrative text uses the same
  OpenRouter model.
- Files are written under `REPORTS_DIR/<16-hex job id>/`.

### Security Boundaries

- `src/security/networkGuard.ts` blocks loopback, private, link-local, metadata,
  reserved, and internal destinations for URL/IP/domain targets and for every
  payload-download redirect hop.
- Analyzer base URLs come only from operator-controlled environment variables.
- Temporary uploads and downloaded payloads are removed after the run.
- Logs are structured JSON with API keys and authorization headers redacted.

---

## Data Flow

```
POST /api/smart-analyze
  → validate passes, resolve upload/target
  → classify input
      deterministic rule → first analyzer tool
      unknown input      → model chooses an available tool
  → graph loop:
      model decision (action + targetId + reasoning)
        → analyzer tool over HTTP → adapter → findings + evidence
        → repeat until pass limit, finish, or budget/deadline
  → optional guarded payload download from latest evidence
  → YARA-X + SIGMA + report stages
  → JSON response with job_id, passes_completed, overall_risk_score,
    findings_summary, report_paths, report_urls
```

The frontend contract is unchanged: it still submits to
`http://localhost:5000/api/smart-analyze` and reads `job_id`,
`findings_summary`, `overall_risk_score`, and `report_urls`.

---

## Related Documentation

- [pipeline-flow.md](pipeline-flow.md) — detailed loop and decision behavior
- [analyzers.md](analyzers.md) — per-analyzer capabilities
- [ts-migration/](ts-migration/) — migration record, parity results, and deviations
- [../backend/Readme.md](../backend/Readme.md) — startup and deployment
