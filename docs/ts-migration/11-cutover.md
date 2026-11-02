# Step 11 — Cutover, parity, and removal of the Python orchestrator

**Status:** complete
**Scope:** run the TypeScript orchestrator alongside the Python baseline,
replay representative inputs, review every difference, switch Docker
Compose/startup/deployment to the TypeScript service, and remove the retired
Python orchestration code.

---

## 1. Verification summary

| Check | Command | Result |
|---|---|---|
| TypeScript typecheck | `npm run typecheck` | pass |
| TypeScript lint | `npm run lint` | pass |
| TypeScript tests | `npm test` | **178 passed, 12 skipped** (live/parity gates) |
| Production build | `npm run build` | pass |
| Parity replay | `SECFLOW_PARITY=1 npx vitest run tests/parity/parity.test.ts` | **3 passed**, 8 scenarios |
| Python baseline tests (before removal) | `.venv/bin/python -m pytest backend/orchestrator/tests -q` | **52 passed** |
| Container build | `docker build -t secflow-orchestrator-ts:step11 backend/orchestrator-ts` | pass |
| Container smoke test | run image with a missing key allowed | `/api/health` `200`, `/api/ready` `503` (model missing, reports writable) |

The parity suite is gated because it needs the Python baseline and its
virtualenv. It spawns the Python Flask test client, replays the same fixtures
through the TypeScript graph, and compares normalized output. The Python
driver monkeypatches report generation and analyzer calls so the comparison is
deterministic and offline.

---

## 2. Parity coverage

`tests/parity/fixtures.json` defines eight representative scenarios:

| Scenario | What it exercises |
|---|---|
| `url-payload-download` | URL → web finding → guarded payload download → malware analysis |
| `url-followup-recon` | URL → web pass → model pivots to recon on an extracted domain |
| `ip-recon` | IPv4 deterministic first pass |
| `domain-recon` | Domain deterministic first pass |
| `uploaded-docm` | Uploaded macro document classification and analysis |
| `uploaded-png` | Uploaded image classification and steg analysis |
| `unknown-string-recon` | No deterministic string rule → model fallback |
| `analyzer-error` | Analyzer failure representation (reviewed difference) |

For each non-error scenario the suite checks:

- analyzer execution order and total pass count;
- normalized findings (temporary input paths removed) and risk scores;
- report `total_passes`, `overall_risk_score`, passes, and findings;
- payload download attempts/successes and temporary-file cleanup;
- stable job ids for target inputs.

It also compares the legacy HTTP surface: `/api/health` body and status, and
`/api/smart-analyze` response keys/values (`job_id`, `passes_completed`,
`overall_risk_score`, `findings_summary`, `report_paths`, `report_urls`).

---

## 3. Reviewed differences

These are intentional and covered by tests. They are not treated as
regressions.

### 3.1 Analyzer failure representation

- **Python:** converted an analyzer exception into a synthetic low-severity
  `error` finding and continued with `risk_score` 0.
- **TypeScript:** records a structured recoverable tool error plus a failed
  `toolHistory` entry. It does not fabricate a SecFlow analyzer result. If the
  run ends with no findings at all, the API returns
  `500 {"error":"Pipeline produced no findings"}`.
- **Why:** keeps analyzer identity/contract honest and avoids presenting an
  infrastructure failure as a security finding. The parity test asserts the
  Python synthetic finding and the TypeScript error/history shape explicitly.

### 3.2 Upload identity and report input

- **Python:** reports used the temporary upload path as `input`; `job_id`
  hashed that per-request path.
- **TypeScript:** reports use the safe display/original filename and `job_id`
  hashes file contents. The same sample therefore reuses its report id instead
  of producing a new id on every upload.
- **Why:** stable, non-leaking identifiers. Target inputs keep identical ids
  because both implementations hash the target string.

### 3.3 Upload size and time limits

- Multipart uploads are capped by `MAX_UPLOAD_BYTES` (default 50 MiB) and
  return `413`; Python had no orchestrator-side upload cap.
- A run that exceeds `TOTAL_ANALYSIS_TIMEOUT_MS` returns `504`; Python had no
  whole-run deadline.
- Analyzer response bodies are capped at 25 MiB to prevent decompiler dumps
  from exhausting memory; an oversized response is a typed analyzer failure.

### 3.4 Network security

- URL/IP/domain targets and every payload-download redirect hop pass through
  the SSRF guard. Loopback, private, link-local, metadata, reserved, internal,
  single-label, credential-bearing, and non-HTTP(S) destinations are rejected
  with `400`.
- DNS failures are allowed by default because an unresolvable name cannot be
  reached; `allowDnsFailure: false` is available for fail-closed deployments.
- `ALLOW_PRIVATE_TARGETS=true` is the explicit local-demo escape hatch and
  still requires HTTP(S) without embedded credentials.
- Python had no equivalent guard.

### 3.5 Additive endpoints and payload behavior

- `GET /api/ready` is new: `200` only when the model key and report directory
  are usable, otherwise `503`.
- Payload downloads remain best-effort and follow the Python intent, but now
  perform per-hop redirect checks, streamed size enforcement, content-type
  classification, analyzer-appropriate extension normalization, and a
  `payload_downloaded` provenance finding.
- Other downloaded content types are skipped rather than forced into an
  incompatible analyzer.

### 3.6 Model and prompt behavior

- Python used Groq `qwen/qwen3-32b` with plain JSON output and a keyword-grep
  fallback.
- TypeScript uses OpenRouter (`nvidia/nemotron-3-ultra-550b-a55b:free` by
  default), structured-output schemas, a validated action allowlist, and
  bounded evidence references. There is no keyword-grep router fallback.
- Decision output budget defaults to `MODEL_MAX_TOKENS` (2048) because
  reasoning-capable models spend reasoning tokens from the same budget.

---

## 4. Deployment changes

`backend/compose.yml` now builds `./orchestrator-ts` and:

- sets `NODE_ENV=production`, `PORT=5000`, and `LOG_LEVEL`;
- passes `OPENROUTER_API_KEY` and `OPENROUTER_MODEL`;
- sets model budgets/timeouts (`MODEL_MAX_CYCLES`, `MODEL_MAX_TOKENS`,
  `MODEL_TIMEOUT_MS`);
- passes all five `ANALYZER_*_URL` values, `ANALYZER_TIMEOUT_MS`,
  `TOTAL_ANALYSIS_TIMEOUT_MS`, `MAX_UPLOAD_BYTES`, and
  `ALLOW_PRIVATE_TARGETS`;
- mounts `./reports:/app/reports` and sets `REPORTS_DIR=/app/reports`;
- uses a Node-based `/api/health` healthcheck.

The old `GROQ_API_KEY`, `MALWARE_ANALYZER_URL`, and `MAX_PASSES` compose
settings are removed. `MAX_PASSES` was never read by Python; the per-request
`passes` query parameter is the loop bound in both implementations.

`.env.example` now documents OpenRouter plus the TypeScript limits. The
analyzer services still receive their own keys (`VIRUSTOTAL_API_KEY`,
`GEMINI_API_KEY` for analyzer-only AI endpoints, recon keys, and Steg database
password).

---

## 5. Removed Python orchestration

After the parity suite passed, the retired service was removed:

- `backend/orchestrator/` (Flask app, Groq/Gemini engine, Python adapters,
  findings store, reporter, tests, Dockerfile, requirements);
- orchestrator-specific Groq configuration from Compose and `.env.example`.

**Not removed:** all five analyzer services, Steg's PostgreSQL/Redis/RQ
containers, analyzer Python dependencies, and analyzer-side Gemini endpoints.

---

## 6. Frontend and analyzer contract checks

- The frontend still posts to `http://localhost:5000/api/smart-analyze` and
  consumes `job_id`, `findings_summary`, `overall_risk_score`, and
  `report_urls`.
- Analyzer service source, routes, request formats, and response shapes are
  unchanged.
- Reports remain available at `/api/report/<job_id>/html` and
  `/api/report/<job_id>/json`.
- The compatibility check in the parity suite compares the complete successful
  API response body against the Python baseline.

---

## 7. Remaining limitations and manual actions

1. DNS rebinding is mitigated, not eliminated. Analyzer containers should have
   egress policy in environments where untrusted URLs are analyzed.
2. The default OpenRouter model and analyzer API keys must be supplied in
   `.env`; deployment without `OPENROUTER_API_KEY` returns `503`.
3. Live OpenRouter and live analyzer tests remain opt-in
   (`OPENROUTER_API_KEY`, `SECFLOW_LIVE_ANALYZERS=1`).
4. `ALLOW_PRIVATE_TARGETS` must stay `false` in production.
5. Reports are JSON + self-contained HTML (PDF via browser print), matching the
   legacy report contract.
