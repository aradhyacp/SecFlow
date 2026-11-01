# Steps 2–3 — TypeScript service shell and OpenRouter model access

**Status:** complete (one manual gate: live OpenRouter call — see §5)

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
    index.ts               runner factory (graph wired in steps 5–8)
  model/
    types.ts               ModelClient interface (provider-agnostic)
    client.ts              Vercel AI SDK adapter (generateText/Output.object)
    provider.ts            @openrouter/ai-sdk-provider construction
tests/                     37 unit/contract tests + 1 gated live test
```

`Dockerfile`, `.env.example`, `.dockerignore`, `pinned package-lock.json` included.

## 2. Configuration (`src/config.ts`)

All parsing/validation is centralised. Invalid values fail fast at startup with a readable list of issues.

| Variable | Default | Notes |
|---|---|---|
| `OPENROUTER_API_KEY` | — | Required in `production`; optional in dev/test so health checks work. |
| `OPENROUTER_MODEL` | `openai/gpt-4.1-mini` | No model id is hardcoded anywhere else. |
| `MODEL_TEMPERATURE` | `0.1` | 0–2 |
| `MODEL_MAX_TOKENS` | `2048` | |
| `MODEL_TIMEOUT_MS` | `60000` | Applied per model call via `AbortSignal.timeout`. |
| `MODEL_MAX_RETRIES` | `2` | SDK-level transient retries. |
| `MODEL_MAX_CYCLES` | `4` | Graph decision/tool cycles (independent of 3/4/5 passes). |
| `ANALYZER_TIMEOUT_MS` | `60000` | Default, overridable per analyzer. |
| `TOTAL_ANALYSIS_TIMEOUT_MS` | `600000` | Whole-run deadline. |
| `ANALYZER_{MALWARE,STEG,RECON,WEB,MACRO}_URL` | Docker-internal URLs | Trailing slashes trimmed. |
| `ANALYZER_*_TIMEOUT_MS` | inherits default | e.g. Ghidra needs 240 s. |
| `MAX_UPLOAD_BYTES` | `52428800` | 50 MB, matches analyzer caps. |
| `ALLOW_PRIVATE_TARGETS` | `false` | SSRF guard toggle (wired in Step 10). |
| `ALLOW_MISSING_OPENROUTER_KEY` | `false` | Dry-run escape hatch; readiness stays 503. |

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

### Model choice evidence (OpenRouter catalogue, fetched 2026-11-01)

`openai/gpt-4.1-mini` is present in the live catalogue with `tools` **and** `structured_outputs` support, 1M context, $0.40/M input / $1.60/M output. 386 of 452 listed models advertise tool support; the default stays overridable through `OPENROUTER_MODEL`.

## 5. Tests

```
cd backend/orchestrator-ts
npm run typecheck   # clean
npm run lint        # clean
npm test            # 37 passed | 1 skipped
```

The skipped test is `tests/integration/openrouter.live.test.ts` — the live OpenRouter structured-output call. It activates automatically when `OPENROUTER_API_KEY` is exported. No key exists in this checkout, so the live call has **not** been executed yet; this is the one outstanding Step 3 gate and is also required for the Step 4 POC.

## 6. Deployment verification

- Docker image builds: `docker build -t secflow-orchestrator-ts:step2 backend/orchestrator-ts`.
- Container runs as non-root, reports `healthy` via the Docker healthcheck, and `/api/health` + `/api/ready` return 200.
- Local start verified separately (health 200, ready 200, report 404, graceful SIGTERM).

## 7. Manual actions

1. Export a real `OPENROUTER_API_KEY` and run `npm test` to execute the live provider test.
