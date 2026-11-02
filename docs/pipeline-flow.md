# SecFlow — Pipeline Flow

This document describes the active TypeScript/LangGraph pipeline, from input
submission to report generation. The analyzer services are unchanged Python
microservices; the orchestrator is `backend/orchestrator-ts/`.

---

## Pipeline Entry Point

`POST /api/smart-analyze?passes=3` accepts:

- a multipart upload in the `file` field;
- JSON with `target`, `url`, or `query`.

`passes` defaults to `3` and must be `3`, `4`, or `5`. Non-numeric values fall
back to `3`, matching the previous Python behavior.

The runner derives a stable `job_id` as the first 16 hex characters of
SHA-256:

- target inputs: the trimmed target string;
- uploads: the file contents (Python used the temporary path, so upload ids
  intentionally differ — see the migration deviations).

---

## Stage 1 — Input Resolution and Classification

```
Input
  ├── multipart upload → temp file (size-capped) → display name retained
  └── JSON target       → trimmed string
        │
        ▼
Classifier
  ├── file: magic bytes + MIME hint + extension
  └── string: URL → IPv4 → domain → email → phone regexes
        │
   ┌────┴─────────────────────────┐
   │ deterministic match          │ no match
   ▼                              ▼
First analyzer fixed        Model chooses from the
(no model call)             tools valid for the input
```

### Deterministic Rules (first match wins)

| Priority | Condition | First analyzer |
|---|---|---|
| 1 | Image magic/MIME (PNG, JPEG, GIF, BMP, TIFF, WEBP) | **steg** |
| 2 | Office/OLE2/OpenXML/RTF MIME, signature, or document extension | **macro** |
| 3 | PE/ELF/Mach-O/MS-DOS executable signature | **malware** |
| 4 | String matches `^https?://` | **web** |
| 5 | String matches the IPv4 regex | **recon** |
| 6 | String matches the domain regex | **recon** |
| 7 | String matches email or phone regex | **recon** |
| 8 | None of the above | model fallback |

For unknown files, the classifier also stores a printable 4 KiB preview. That
preview is wrapped as untrusted evidence in the decision prompt; the file
itself is never sent to the model. Unknown strings expose `analyze_recon`;
unknown files expose the applicable file analyzers.

---

## Stage 2 — LangGraph Analysis Loop

The graph is a single state machine:

```
START → decide ──tool──→ act ──→ decide ──→ ... ──→ END
             └──finish / limit / error ────────────┘
```

### `decide`

Before calling the model, the node checks configured limits and builds the
allowlist of valid `(tool, targetId)` actions:

- requested pass count reached → `max_passes`;
- `MODEL_MAX_TOOL_CALLS` reached → `max_tool_calls`;
- `MODEL_MAX_CYCLES` reached → `max_cycles`;
- no valid action remains → `no_artifacts` (or `unsupported_input` before any
  pass).

On pass 1, a deterministic classifier match selects the analyzer without a
model call. Otherwise the node builds a decision prompt from bounded findings
and evidence references and calls the OpenRouter model with a dynamic Zod
schema:

```ts
{
  action: "analyze_malware" | "analyze_steg" | "analyze_recon" |
          "analyze_web" | "analyze_macro" | "generate_yara" |
          "generate_sigma" | "generate_report" | "finish",
  targetId: string | null,
  reasoning: string
}
```

The decision is re-validated in the graph:

- the tool must be in the current action allowlist;
- a non-null `targetId` must resolve in the trusted target catalog;
- the exact tool/target pair must not have already run;
- `finish` must use a null target id.

A duplicate decision terminates with `duplicate_analysis`; invalid or failed
model output terminates with `fatal_error`. A well-formed `finish` triggers the
optional payload-download attempt below.

### `act`

The selected tool runs with `{ targetId }` only. Analyzer adapters translate
the native response into the SecFlow contract, and the result is appended to
graph state with pass number, analyzer, finding count, risk score, duration,
and a raw-output reference.

- Successful results can create artifact targets (URLs, IPs, domains) for the
  next decision.
- A failed tool records a structured tool error and history entry, then returns
  to `decide`; the run continues if other evidence/actions remain.
- Unknown targets, tool/target mismatches, and invalid tool output terminate the
  graph as fatal errors.

### Termination Reasons

| Reason | Meaning |
|---|---|
| `max_passes` | Requested 3/4/5 analyzer passes completed |
| `model_finished` | Model returned `finish` and no payload was downloadable |
| `no_artifacts` | Every permitted tool/target pair has been attempted |
| `duplicate_analysis` | Model selected an already-attempted tool/target pair |
| `max_cycles` | Model decision budget exhausted |
| `max_tool_calls` | Analyzer tool budget exhausted |
| `timeout` | Run deadline/abort signal fired |
| `fatal_error` | Invalid model output or fatal tool/validation failure |
| `unsupported_input` | No analyzer can handle the classified input |

---

## Stage 3 — Payload Download and Re-Analysis

When the model returns `finish`, the orchestrator inspects the latest pass for
HTTP URL candidates that have not already been downloaded. For each candidate:

1. The **network guard** validates the destination and every redirect hop.
2. The downloader follows redirects manually, streams with a 50 MiB cap, and
   rejects oversized or unsupported content.
3. Content type and extension choose an analyzer:
   - images → steg;
   - Office/RTF documents → macro;
   - executables → malware;
   - other downloaded content is skipped.
4. The file is renamed to an extension the target analyzer accepts, registered
   as a `payload_download` target with provenance, and analyzed.
5. A `payload_downloaded` finding is prepended to the resulting evidence.

Downloads are best-effort: a failed/skipped candidate is logged and the run
continues. Temporary files are removed in the runner's `finally` block.

---

## Stage 4 — Rules and Report

After the loop, `finalizeAnalysis` runs:

1. **`generate_yara`** — the model proposes rules citing evidence; YARA-X
   compiles each rule and rejects invalid syntax.
2. **`generate_sigma`** — the model proposes SIGMA rules; schemas and required
   structural fields are validated.
3. **`generate_report`** — builds the PWNDoc-compatible JSON and self-contained
   HTML report under `REPORTS_DIR/<job_id>/`. Optional narrative text is
   generated by the same model; a narrative failure does not discard the report.

Rule/report failures are recorded as errors/history entries. If the final report
cannot be produced, the API returns `500`.

---

## Stage 5 — API Response and Error Mapping

Successful response (unchanged frontend contract):

```json
{
  "job_id": "0123456789abcdef",
  "passes_completed": 2,
  "overall_risk_score": 8.5,
  "findings_summary": [ ...SecFlow results... ],
  "report_paths": { "json": "...", "html": "..." },
  "report_urls": {
    "json": "/api/report/0123456789abcdef/json",
    "html": "/api/report/0123456789abcdef/html"
  }
}
```

| Condition | HTTP |
|---|---|
| Invalid passes, target, or upload | `400` / `413` |
| SSRF-blocked target or redirect | `400` |
| Missing `OPENROUTER_API_KEY` / model unavailable | `503` |
| Total-run deadline or abort | `504` |
| No findings, report failure, other fatal error | `500` |

`passes_completed` is the number of analyzer result entries, matching Python's
`len(all_findings)`.

---

## Observability

Each run carries an `x-request-id` (accepted or generated) and a stable
`job_id`. Structured JSON logs include:

- `run_started` / `run_completed` / `run_failed`;
- `graph_transition`;
- `decision` (deterministic or model, tool/target, reasoning);
- `model_call` (operation, model, duration, token usage);
- `tool_call` (tool, target id, status, risk, findings, duration);
- `analyzer_retry` and `payload_download` events.

Prompts, raw sample bytes, analyzer response bodies, and API keys are not
logged. Authorization/cookie headers and key-like strings are redacted.

---

## Related Documentation

- [architecture.md](architecture.md) — component diagram and boundaries
- [ts-migration/06-decision-loop.md](ts-migration/06-decision-loop.md) — decision-loop design
- [ts-migration/09-reliability-security.md](ts-migration/09-reliability-security.md) — security and failure handling
- [ts-migration/11-cutover.md](ts-migration/11-cutover.md) — parity results and known deviations
