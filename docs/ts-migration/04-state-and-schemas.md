# Step 5 — Shared graph state and schemas

**Status:** complete.

## State

`src/graph/state.ts` defines `AnalysisStateAnnotation`, the typed LangGraph
state for the orchestrator. It covers everything Step 5 requires:

| Field | Purpose |
|---|---|
| `runId` | Correlation id (also in every log line) |
| `source` | Original input: file/target, display name, original name, MIME, size (never a temp path in prompt-visible fields) |
| `inputType` | `image`, `document`, `executable`, `url`, `ip`, `domain`, `email`, `phone`, `username`, `unknown` |
| `target` | Current classified target with a trusted backend-resolved value |
| `targets` | Deduplicated target catalog (input + extracted artifacts + downloaded payloads) |
| `indicators` | Extracted IOCs with provenance, kept as untrusted evidence |
| `classification` | Deterministic classifier output or model fallback decision |
| `context` | Run id, timestamps, max passes/cycles/tool calls, model id |
| `findings` | Append-only `SecFlowResult[]` in the existing contract |
| `toolHistory` | Tool, pass, target id, status, duration, risk, raw-output ref, concise summary |
| `errors` | Stage/code/message/recoverable/timestamp |
| `rules` | YARA and SIGMA artifacts with validation status and evidence refs |
| `report` | Report status, risk, summary, recommendations, output paths |
| `termination` | `null` while running; explicit reason/pass/detail once stopped |
| `counters` | Passes, cycles, tool calls, duplicate rejections |

Array channels append; `targets` merges by id; scalar channels replace.
`analysisStateSchema` is the validation boundary for initial state, persistence
and tests.

## Schemas

`src/graph/schema/analyzer.ts`
- `secFlowFindingSchema`, `secFlowResultSchema` — the existing contract,
  including the severity vocabulary and 0–10 risk bound.
- `rawOutputRefSchema` — id, analyzer, pass, byte size, SHA-256, 2 000-char
  preview.
- `analyzerToolOutputSchema` — the concise projection returned to the model
  (max 200 findings, summary, ref, no full raw output).
- `severityRiskScore()` / `summarizeFindings()` — shared helpers matching the
  Python weights (critical 4.0, high 2.5, medium 1.0, low 0.3, info 0.0) and
  cap-at-10 behaviour.

`src/graph/schema/tools.ts`
- One input schema per tool. Analyzer tools accept **only** `{ targetId }`;
  YARA/SIGMA/report tools accept **only** `{}`. A model cannot supply a path,
  URL, shell command, rule text, or service address.
- Tool name enum: `analyze_malware`, `analyze_steg`, `analyze_recon`,
  `analyze_web`, `analyze_macro`, `generate_yara`, `generate_sigma`,
  `generate_report`.
- Output schemas for analyzer, rule and report tools.

`src/graph/schema/rules.ts`
- Rule artifact, rules state and rule-generation output schemas, including
  validation errors and evidence references.

`src/graph/untrusted.ts`
- `wrapUntrusted()` caps content at 16 000 chars and marks it `trust:
  "untrusted"`.
- `formatUntrusted()` wraps content in `<untrusted_evidence>` tags.
- `UNTRUSTED_DATA_POLICY` is the text prompt builders must place next to
  evidence. Enforcement still lives in schemas/allowlists, not in the prompt.

## Raw output storage

`src/graph/rawOutputStore.ts` defines `RawOutputStore` and an in-memory
implementation. Full analyzer output—Ghidra decompilation, objdump, macro
source—is stored outside graph state; state/prompts receive a `RawOutputRef`
with a short preview and SHA-256. A filesystem-backed implementation can be
added without changing state or tool contracts.

## Tests

`tests/graph-state.test.ts` covers:

- parsing every `findings_summary` entry from the recorded fixture;
- rejection of unknown severities, risk > 10 and extra contract keys;
- risk weights/capping and concise finding summaries;
- tool input schemas rejecting paths, URLs, commands and free-form rule text;
- complete state validation and append/dedupe reducer behaviour in a compiled
  LangGraph graph;
- untrusted wrapping/truncation and prompt labelling;
- raw output refs, preview limits, hashing and retrieval.

Current suite: **63 passed, 2 skipped (live OpenRouter only)**.
