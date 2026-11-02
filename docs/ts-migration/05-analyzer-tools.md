# Step 6 — Analyzer tools

**Status:** complete (fixture and HTTP integration verified; live analyzer APIs gated).

Each existing analyzer is exposed as one LangGraph-callable tool. Tools call the
unchanged analyzer services over HTTP; no analyzer source is imported into the
orchestrator.

## Tool inventory

| Tool              | Analyzer  | Service routes                                                                                                                                                                 | Accepted target kinds                        |
| ----------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------- |
| `analyze_malware` | `malware` | `POST /file-analysis`, `POST /decompile`                                                                                                                                       | `file`                                       |
| `analyze_steg`    | `steg`    | `POST /upload` → `GET /status/:hash` → `GET /result/:hash`                                                                                                                     | `file`                                       |
| `analyze_recon`   | `recon`   | `POST /scan` for IP/domain, `POST /footprint` for email/phone/username                                                                                                         | `ip`, `domain`, `email`, `phone`, `username` |
| `analyze_web`     | `web`     | twelve sequential `GET` routes (`status`, `security-headers`, `tls`, `ssl`, `hsts`, `firewall`, `redirects`, `headers`, `redirect-chain`, `malware-check`, `url-parse`, `dns`) | `url`                                        |
| `analyze_macro`   | `macro`   | `POST /analyze`                                                                                                                                                                | `file`                                       |

The malware client attempts VirusTotal and decompilation independently and merges
both responses before adapting, matching the Python caller. The web client keeps
the Python route order and per-route timeouts.

## Argument security

Model-generated arguments are **only** `{ targetId }` (`targetRefSchema`). A tool
never accepts a path, URL, shell command, raw indicator or service address.

At execution time the tool:

1. resolves `targetId` against the trusted `ToolContext.targets` catalog;
2. rejects unknown ids and lists the available ids in the error;
3. rejects a valid id whose `kind` is not allowed for that tool;
4. reads the target's backend-resolved `value` and calls the client with it.

Uploads that need a different extension (for example an extracted payload with no
extension) are copied to a temporary `.bin` by `withAllowedExtension`; the
original upload is never renamed. The model never sees either path.

Only tools relevant to the current target are exposed by the Step 7 decision
loop. Tool descriptions state when each tool applies and that a `targetId` is
required.

## Timeouts and retries

`src/analyzers/http.ts` implements `requestJson`:

- hard per-request timeout via `AbortSignal.timeout`;
- caller abort propagation via `AbortSignal.any`;
- bounded exponential retry (capped at 5 s) for network errors, timeouts,
  `429`, `500`, `502`, `503` and `504`;
- no retry for other `4xx`, invalid JSON, or after caller abort;
- normalized `AnalyzerHttpError` with status, retriable flag and a 2 000-char
  body preview.

Defaults:

| Analyzer                      | Timeout                      | Retries                    |
| ----------------------------- | ---------------------------- | -------------------------- |
| malware `/file-analysis`      | 60 s                         | 0                          |
| malware `/decompile`          | 180 s                        | 0                          |
| steg upload / status / result | 30 s / 10 s / 30 s           | 0                          |
| steg total polling            | 300 s                        | —                          |
| recon                         | `ANALYZER_TIMEOUT_MS` (60 s) | `ANALYZER_MAX_RETRIES` (1) |
| web                           | per route 10–30 s            | `ANALYZER_MAX_RETRIES` (1) |
| macro                         | `ANALYZER_TIMEOUT_MS` (60 s) | 0                          |

`ANALYZER_<NAME>_TIMEOUT_MS` overrides a service timeout. `ANALYZER_MAX_RETRIES`
is bounded to 0–5. File-upload analyzers always use zero retries so a transient
failure cannot trigger a duplicate heavy scan.

Analyzer failures are normalized into findings, not thrown: clients catch HTTP
errors, log them, and adapt an error payload. A failed macro scan produces
`macro_clean` findings with risk `0.5`, matching Python. The web client skips a
failed route and adapts the routes that succeeded.

## Response normalization

`src/analyzers/adapters/` ports the Python adapters one-for-one:

- `malware.ts` — VirusTotal stats/engine detections, decompilation and objdump;
- `steg.ts` — per-tool status and extracted files;
- `recon.ts` — geolocation, Talos, Tor, Tranco, ThreatFox and footprint results;
- `web.ts` — status, headers, TLS/SSL, HSTS, WAF, redirects, malware and URL
  parsing;
- `macro.ts` — macro streams, keywords, IOCs and VirusTotal verdicts.

Every adapter returns `{ findings, riskScore, rawOutput, extractedFiles? }`.
`severityRiskScore` keeps the Python weights and 10.0 cap. The web TLS cipher is
JSON-serialized when the service returns an object instead of Python printing its
object representation; this is the only intentional formatting difference.

Tool output has two projections (`src/analyzers/schema.ts`):

- `modelOutput` — analyzer/pass/target id, at most 50 findings with detail and
  evidence truncated to 500 chars, a 4 000-char summary, finding count, risk,
  extracted files and a `RawOutputRef`;
- `secFlow` — the full existing contract (`analyzer`, `pass`, `input`,
  `findings`, `risk_score`, `raw_output`, optional `extracted_files`).

`toModelOutput` returns only `modelOutput`. Full output is stored in
`RawOutputStore`; state and prompts receive a reference with byte size, SHA-256
and a 2 000-char preview.

## Tests

Fixture contract tests (`tests/analyzers.test.ts`):

- every adapter against the recorded analyzer fixtures;
- expected risk scores and finding types, including the clean malware and failed
  macro paths.

HTTP integration tests (`tests/analyzer-tools.test.ts`):

- a local HTTP server implements the real analyzer routes from the fixtures;
- each of the five tools runs end-to-end through `ToolRegistry.execute`;
- malware full output is retrievable by reference while the model projection is
  bounded and contains no `raw_output` field;
- unknown target ids and wrong target kinds are rejected before any request.

HTTP policy tests (`tests/http.test.ts`):

- success parsing, timeout, 503 retry, no retry on 4xx/invalid JSON, bounded
  network-failure retries, caller abort propagation.

Live API tests (`tests/integration/analyzers.live.test.ts`) are skipped unless
`SECFLOW_LIVE_ANALYZERS=1`. They use `examples/RealMalware.exe`,
`examples/nuclear_motor_example.docm` and `backend/Steg-Analyzer/example/example1.png`,
and default to the compose host ports (5001/5002/5003/5005/5006):

```bash
SECFLOW_LIVE_ANALYZERS=1 npm test
```

Current suite: **90 passed, 7 skipped** (2 OpenRouter live, 5 analyzer live).
