# Steps 2–3 — TypeScript service shell and OpenRouter model access

**Status:** complete, including the live OpenRouter gate.

---

## 1. Service layout

New service: `backend/orchestrator-ts/` (runs alongside the Python orchestrator until Step 11).

```
src/
  index.ts                 process bootstrap, graceful shutdown
  app.ts                   Express app factory (deps injected)
  config.ts                Zod-validated environment → AppConfig
  logger.ts                pino structured logger + secret redaction
  http/
    errors.ts              HttpError / AnalyzerError / ModelContractError
    middleware.ts          flask-cors-equivalent CORS + JSON error handler
  routes/
    health.ts              GET /api/health (legacy payload), GET /api/ready
    analyze.ts             POST /api/smart-analyze?passes=N
    reports.ts             GET /api/report/:jobId/:fmt
  pipeline/
    types.ts               SecFlow contract, ResolvedInput, AnalysisRunner
    resolveInput.ts        multipart → temp file, JSON → target
    index.ts               production runner: input hash, run-scoped tools,
                           finalize/report, timeout and error mapping
  security/
    networkGuard.ts        SSRF policy for URL/IP/domain targets
  model/
    types.ts               ModelClient interface (provider-agnostic)
    client.ts              Vercel AI SDK adapter (generateText/Output.object)
    provider.ts            @openrouter/ai-sdk-provider construction
tests/                     unit/contract tests plus environment-gated live tests
```

`Dockerfile`, `.env.example`, `.dockerignore`, `pinned package-lock.json` included.

## 2. Configuration (`src/config.ts`)

All parsing/validation is centralised. Invalid values fail fast at startup with a readable list of issues.

| Variable                                      | Default                                  | Notes                                                                           |
| --------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------- |
| `OPENROUTER_API_KEY`                          | —                                        | Required in `production`; optional in dev/test so health checks work.           |
| `OPENROUTER_MODEL`                            | `nvidia/nemotron-3-ultra-550b-a55b:free` | No model id is hardcoded anywhere else.                                         |
| `MODEL_TEMPERATURE`                           | `0.1`                                    | 0–2                                                                             |
| `MODEL_MAX_TOKENS`                            | `2048`                                   |                                                                                 |
| `MODEL_TIMEOUT_MS`                            | `60000`                                  | Applied per model call via `AbortSignal.timeout`.                               |
| `MODEL_MAX_RETRIES`                           | `2`                                      | SDK-level transient retries.                                                    |
| `MODEL_MAX_CYCLES`                            | `12`                                     | Model decisions per run; 12 covers the 5-pass max plus finish/validation slack. |
| `MODEL_MAX_TOOL_CALLS`                        | `20`                                     | Hard cap on analyzer-tool executions per run.                                   |
| `ANALYZER_TIMEOUT_MS`                         | `60000`                                  | Default, overridable per analyzer.                                              |
| `ANALYZER_MAX_RESPONSE_BYTES`                 | `26214400`                               | 25 MiB body cap; oversized responses fail without being buffered.               |
| `TOTAL_ANALYSIS_TIMEOUT_MS`                   | `600000`                                 | Whole-run deadline.                                                             |
| `ANALYZER_{MALWARE,STEG,RECON,WEB,MACRO}_URL` | Docker-internal URLs                     | Trailing slashes trimmed.                                                       |
| `ANALYZER_*_TIMEOUT_MS`                       | inherits default                         | e.g. Ghidra needs 240 s.                                                        |
| `MAX_UPLOAD_BYTES`                            | `52428800`                               | 50 MB, matches analyzer caps.                                                   |
| `ALLOW_PRIVATE_TARGETS`                       | `false`                                  | SSRF guard toggle; enforced before the graph and in every analyzer tool.        |
| `ALLOW_MISSING_OPENROUTER_KEY`                | `false`                                  | Dry-run escape hatch; readiness stays 503.                                      |

## 3. HTTP compatibility

Verified by tests (`tests/app.test.ts`, `tests/analyze.test.ts`):

- `GET /api/health` → identical payload to Python: `{"status":"healthy","service":"secflow-orchestrator"}`.
- `GET /api/ready` → new; 200 only when model key + writable reports dir exist, else 503.
- `POST /api/smart-analyze` → same response keys (`job_id`, `passes_completed`, `overall_risk_score`, `findings_summary`, `report_paths`, `report_urls`).
- Pass parsing mirrors Python: non-numeric → 3; numeric outside {3,4,5} → 400 `passes must be 3, 4, or 5`.
- Body resolution mirrors Python: multipart `file` first, else JSON `target|url|query`; otherwise the same 400 message.
- `GET /api/report/:jobId/:fmt` → hex-only job id, 400 unknown format, 404 missing report, JSON as attachment with `secflow_report_<id>.json`.
- CORS `*` like `flask-cors`.
- Uploads are written to a temp dir (never sent to the model) and deleted in a `finally` block.

Documented behaviour changes (intentional):

- Multipart uploads are capped at `MAX_UPLOAD_BYTES` (413). Python had no cap; analyzers cap at 50 MB / 3 MB anyway.
- `/api/ready` is additive.
- A whole-run timeout can return 504 (Python had none).

## 4. Model layer

- `@openrouter/ai-sdk-provider@3.1.0` + `ai@7.0.159`, pinned in `package-lock.json`.
- `createOpenRouter({ apiKey, compatibility: "strict", appName: "SecFlow" }).chat(modelId)` is the **only** place a provider/model is constructed.
- `ModelClient` is the sole surface the graph will use (`decide()` for tool calls, `generateObject()` for structured stages). This is the provider-compatibility gate: a later switch to `@langchain/openrouter` only changes `src/model/`.
- `decide()` runs exactly one AI SDK step (`stepCountIs(1)`) and returns tool calls; tools deliberately have **no `execute`**, so the graph controls execution and feeds results back. This is the verified adapter pattern for the LangGraph POC.
- `generateObject()` uses the current `generateText({ output: Output.object({ schema }) })` API (AI SDK 7 deprecates `generateObject`), converting schema failures into `ModelContractError`.

### Model choice (updated 2026-11-02)

The default is `nvidia/nemotron-3-ultra-550b-a55b:free` (NVIDIA Nemotron 3
Ultra free tier). OpenRouter reports a 1M-token context, free input/output
pricing, and support for `tools`, `tool_choice`, temperature, and reasoning
parameters. The catalogue does not advertise `structured_outputs` for this
model, but the AI SDK `Output.object` path and all gated live tests — structured
classification, decision allowlisting, and report narrative — passed against it.

The default remains overridable through `OPENROUTER_MODEL`. The earlier Step 3
evidence used `openai/gpt-4.1-mini`; that run is historical rather than a claim
about the current default.

## 5. Tests

```
cd backend/orchestrator-ts
npm run typecheck   # clean
npm run lint        # clean
npm test            # 163 passed | 9 skipped without a key
```

The skipped tests include the live OpenRouter calls
(`tests/integration/openrouter.live.test.ts`,
`tests/integration/prompts.live.test.ts`, and
`tests/integration/langgraph.live.test.ts`). They activate automatically when
`OPENROUTER_API_KEY` is exported. They were rerun against
`nvidia/nemotron-3-ultra-550b-a55b:free` on 2026-11-02 and passed, covering the
Step 3 structured-output exit criterion, the Step 4 live graph gate, and the Step
9 prompt gates.

## 6. Deployment verification

- Docker image builds: `docker build -t secflow-orchestrator-ts:step2 backend/orchestrator-ts`.
- Container runs as non-root, reports `healthy` via the Docker healthcheck, and `/api/health` + `/api/ready` return 200.
- Local start verified separately (health 200, ready 200, report 404, graceful SIGTERM).
