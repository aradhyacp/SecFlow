# Step 10 — Reliability, security, and observability

**Status:** complete
**Scope:** production runner wiring, per-run logging, execution limits, SSRF
protection, analyzer endpoint validation, failure mapping, and the tests that
cover the Step 10 exit criteria.

---

## 1. Production runner

`src/pipeline/index.ts` now implements `AnalysisRunner` instead of returning a
`501` stub. A request flows through:

1. **Run identity** — `x-request-id` is accepted when it is 1–200 characters;
   otherwise a UUID is generated. The same id becomes the pino child-logger
   binding and the graph `runId`.
2. **Stable report id** — `sha256(input)[:16]`:
   - target inputs hash the trimmed target string;
   - uploads hash the file contents, so the same sample reuses its report id
     instead of Python's per-request temp-path hash.
3. **Run-scoped registry** — the five analyzer tools, YARA tool, SIGMA tool, and
   report tool are constructed with the run logger. Analyzer clients therefore
   emit retry/error logs with `runId` already bound.
4. **Graph execution** — classifier → deterministic first pass → bounded
   model/tool loop, with the network guard and total-run `AbortSignal`.
5. **Finalization** — YARA, SIGMA, then the report, using the same validated
   graph state. The optional report narrative is wired to the run model.
6. **Legacy response** — `jobId`, `passesCompleted`, `overallRiskScore`,
   `findingsSummary`, `reportPaths`, and `reportUrls` keep the Python shape.

`passesCompleted` is the number of analyzer result entries, matching Python's
`len(all_findings)`. An empty result set returns
`500 {"error":"Pipeline produced no findings"}` before report generation.

### Error mapping

| Condition                                                          | HTTP result                    |
| ------------------------------------------------------------------ | ------------------------------ |
| Prohibited network target                                          | `400` with the guard reason    |
| Missing `OPENROUTER_API_KEY` / no model available                  | `503`                          |
| `TOTAL_ANALYSIS_TIMEOUT_MS` or an aborted run signal               | `504`                          |
| Empty findings, report failure, or other uncaught pipeline failure | `500`                          |
| Invalid client input / passes / upload                             | existing `400`/`413` behaviour |

The runner logs a normalized `run_failed` event and rethrows the mapped error.

---

## 2. Structured logs and redaction

Every production request emits JSON logs with `runId`; most events also carry
`jobId`, `event`, `durationMs`, and the relevant tool/target identifiers.

| Event                          | Where         | Key fields                                               |
| ------------------------------ | ------------- | -------------------------------------------------------- |
| `run_started`                  | runner        | input kind, byte/length count, max passes, model         |
| `analysis_loop_completed`      | runner        | status, termination reason, pass/finding counts          |
| `graph_transition`             | graph         | from/to node, tool/target, termination detail            |
| `decision`                     | graph         | deterministic/model source, pass, tool/target, reasoning |
| `model_call`                   | model adapter | operation, model, duration, token usage                  |
| `tool_call`                    | graph         | tool, target id, status, risk, finding count, duration   |
| `analyzer_retry`               | analyzer HTTP | label, attempt, delay, elapsed duration                  |
| `run_completed` / `run_failed` | runner        | duration, risk/report status or normalized error         |

Redaction rules:

- Pino redacts authorization/cookie headers and `apiKey`/`OPENROUTER_API_KEY`
  property names.
- `redactSensitive()` strips OpenAI/OpenRouter-style keys and long hex tokens
  from normalized runner errors.
- Raw sample bytes, analyzer response bodies, parser body previews, prompts, and
  raw model output are never logged.
- The run-start log does not include the display name, which may be a filename,
  email address or phone number. Targets appear in logs only as hashed target
  ids; the report still uses the safe display name.
- Tool errors are truncated to 2,000 characters for logs. Analyzer adapters
  continue to return their normal error findings to the report.

> Logging is not a substitute for data-handling policy: analyzer error text can
> still contain a hostname or URL supplied as the target. Deployments handling
> personal data should set `LOG_LEVEL=info` or higher and apply their normal log
> retention rules.

---

## 3. Execution limits

| Limit                         | Default | Enforcement                                                         |
| ----------------------------- | ------- | ------------------------------------------------------------------- |
| `MODEL_MAX_CYCLES`            | 12      | graph decision counter, includes rejected decisions                 |
| `MODEL_MAX_TOOL_CALLS`        | 20      | graph counter, checked before every tool execution                  |
| `MODEL_MAX_TOKENS`            | 2048    | per decision; reasoning tokens share this budget                    |
| `MODEL_TIMEOUT_MS`            | 60 s    | per model call, combined with the run signal                        |
| `MODEL_MAX_RETRIES`           | 2       | SDK retries for transient model failures                            |
| `ANALYZER_TIMEOUT_MS`         | 60 s    | default per analyzer route; per-service overrides remain            |
| `ANALYZER_MAX_RETRIES`        | 1       | recon/web transient retries; upload analyzers stay at 0             |
| `ANALYZER_MAX_RESPONSE_BYTES` | 25 MiB  | streaming body cap; oversized bodies are cancelled, not buffered    |
| `TOTAL_ANALYSIS_TIMEOUT_MS`   | 600 s   | request signal through graph, clients, finalization and post-checks |
| `MAX_UPLOAD_BYTES`            | 50 MiB  | multer limit                                                        |
| Duplicate tool/target         | —       | rejected by the graph before execution                              |

Reasoning-capable models spend reasoning tokens from the same output budget.
The earlier 500-token decision cap was enough for a bare JSON object but live
Nemotron runs consumed ~250 reasoning tokens and truncated the JSON before the
final fields. Decisions now default to `MODEL_MAX_TOKENS` (2048), and the live
prompt gate uses the same budget.

YARA/SIGMA/report model calls happen after the decision loop. They are covered
by the per-model timeout and the total-run signal, but not by
`MODEL_MAX_CYCLES`; `MODEL_MAX_TOOL_CALLS` applies only to the five analyzers.

---

## 4. SSRF policy

`src/security/networkGuard.ts` is applied twice:

1. to the classified initial target before the graph starts;
2. inside every analyzer tool, so model-created artifact targets are checked
   before a network-capable analyzer sees them.

Artifact construction also applies a fast, DNS-free filter for obvious
loopback/metadata/internal names before a target is offered to the model.

Blocked by default:

- IPv4 loopback (`127.0.0.0/8`), private (`10/8`, `172.16/12`, `192.168/16`),
  link-local/metadata (`169.254/16`, including `169.254.169.254`), the Azure
  platform address `168.63.129.16`, CGNAT (`100.64/10`), multicast/reserved
  (`224/4`, `240/4`), documentation, benchmarking and other reserved ranges;
- IPv6 loopback/unspecified, unique-local (`fc00::/7`), link-local
  (`fe80::/10`), multicast, documentation, Teredo, benchmarking, NAT64, and
  IPv4-mapped/compatible addresses that embed a prohibited IPv4 destination;
- `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, `*.lan`,
  `metadata.google.internal`, `metadata`, `instance-data`, and single-label
  hostnames that could resolve through a local search domain;
- URL credentials, non-HTTP(S) schemes, malformed URLs, and IPv6 zone ids;
- any hostname whose DNS resolution returns a prohibited address.

Hostnames are resolved through an injectable `HostLookup`, which keeps guard
tests deterministic. DNS failure is allowed by default because an unresolvable
name cannot be reached; `allowDnsFailure: false` provides fail-closed behaviour.
`ALLOW_PRIVATE_TARGETS=true` is the explicit local-demo escape hatch.

### Residual risk

- DNS rebinding remains a TOCTOU risk: the guard resolves a name at decision
  time, while the analyzer resolves it again when fetching. The orchestrator
  cannot close that gap alone. Production deployments should add egress
  filtering / network policy to analyzer containers.
- The TypeScript orchestrator does not perform Python's opportunistic payload
  download. URLs discovered in evidence remain URL targets and are analyzed by
  the web analyzer; any future download stage must call the same guard before
  fetching. This is a Step 11 parity item.

---

## 5. Analyzer isolation and endpoint control

- Analyzer base URLs come only from operator-controlled environment variables.
  They are validated as HTTP(S) URLs without embedded credentials; model output
  cannot supply or alter them.
- Tool schemas expose only `{ targetId }`, and target ids must resolve in the
  trusted per-run target catalog.
- There is no shell tool, file-write tool, or arbitrary HTTP tool available to
  the model. YARA/SIGMA/report tools accept `{}` and write only under
  `REPORTS_DIR/<16-hex job id>/`.
- Analyzer retries are bounded and the orchestrator does not automatically retry
  a completed tool/target pair.
- Container-level isolation (no host mounts, restricted egress, non-root user,
  resource limits) remains a deployment responsibility; the app does not grant
  analyzers access to the orchestrator filesystem or credentials.

---

## 6. Tracing

Tracing is log-based and mandatory-free:

- the request id is returned in `x-request-id` and bound to every run log;
- graph transitions, decisions, model calls, tool calls, retries, durations and
  normalized failures share that id;
- no external tracing service, SDK, collector, or account is required for local
  development.

The event names above are stable enough to forward to an OpenTelemetry/log
pipeline later, but Step 10 deliberately avoids adding infrastructure the
project does not already run.

---

## 7. Test coverage for the exit criteria

| Exit criterion                      | Tests                                                                                                                                                                                                                           |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Timeout                             | `http.test.ts` per-request timeout; `pipeline.test.ts` expired total signal → 504                                                                                                                                               |
| Retry                               | `http.test.ts` transient 503 recovery, no retry for 400/invalid JSON/abort                                                                                                                                                      |
| Malformed model output              | `model.test.ts` provider contract error; `prompts.test.ts` invalid decision shapes                                                                                                                                              |
| Invalid tool arguments              | `graph-state.test.ts` path/URL-shaped target ids; `analyzer-tools.test.ts` unknown/mismatched targets                                                                                                                           |
| Unavailable analyzer                | `pipeline.test.ts` all analyzers failing → 500 no findings; `analysis-loop.test.ts` tool failure without graph crash; `finalize.test.ts` unavailable generation tools                                                           |
| Prompt injection in analyzer output | `prompts.test.ts` injected instructions remain inside the untrusted block and cannot expand tools/schema                                                                                                                        |
| Prohibited network destinations     | `networkGuard.test.ts` literals, DNS-resolved private addresses, mixed answers, metadata names, URL schemes/credentials, artifact filter; `pipeline.test.ts` guard runs before any tool; `analyze.test.ts` route maps it to 400 |
| Response-size limit                 | `http.test.ts` oversized streamed body is rejected without retry                                                                                                                                                                |

Additional runner tests verify the legacy response shape, report files, stable
job id, and no-findings behaviour.

Verification run:

```bash
cd backend/orchestrator-ts
npm run typecheck
npm run lint
npm test          # 163 passed, 9 skipped without OPENROUTER_API_KEY
npm run build
```

Live OpenRouter/analyzer tests remain gated by `OPENROUTER_API_KEY` and
`SECFLOW_LIVE_ANALYZERS=1`.

---

## 8. Known limitations and follow-ups

1. DNS rebinding is mitigated, not eliminated; add analyzer egress policy.
2. The TS flow has no orchestrator-side payload download stage yet (Step 11
   parity review).
3. Optional YARA/SIGMA/report model work is outside the decision-loop budgets,
   bounded instead by model timeout, retries and the total-run deadline.
4. Logs are structured JSON only; there is no OpenTelemetry exporter.
5. `npm run format:check` still reports pre-existing Prettier differences in
   earlier migration files; typecheck, lint and build are clean.
