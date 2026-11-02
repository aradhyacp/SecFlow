# Step 7 — Analysis decision loop

**Status:** complete.

The orchestrator graph now runs the real analysis loop:

```
START → decide → act → decide → … → END
```

`decide` either applies a deterministic first-pass rule, asks the model for one
structured action, or records a termination reason. `act` executes exactly one
registered analyzer tool and feeds the normalized result back into state.

## Deterministic classification

`src/classifier/` ports the Python classifier without the `file`/python-magic
binaries:

- `rules.ts` — routing order URL → IPv4 → domain → email → phone for strings;
  image → Office/RTF document → executable for files.
- `sniff.ts` — magic-byte detection for PNG/JPEG/GIF/BMP/TIFF/WebP, ZIP, OLE2,
  RTF, PE, ELF and Mach-O.
- `classifier.ts` — builds the initial `AnalysisTarget` and `Classification`,
  validates target length/readability, and marks unknown inputs
  `deterministic: false`.

When a deterministic rule matches, the first analyzer runs **without a model
call**. Unknown file inputs expose all three file tools so the model can choose;
unknown string inputs terminate `unsupported_input` because no tool can accept
them. Email and phone strings route to recon `/footprint`.

## Structured decisions

`src/graph/decision.ts` defines the model contract:

```json
{
  "action": "analyze_malware | analyze_steg | analyze_recon | analyze_web | analyze_macro | finish",
  "targetId": "tgt_… (required unless action=finish)",
  "reasoning": "one sentence citing the evidence"
}
```

The provider receives a narrowed enum containing only currently available tools
plus `finish`. The action is never parsed from prose or free-form JSON. Graph-side
validation repeats the check because model output is untrusted:

1. `analysisDecisionSchema` validates shape and id format;
2. `finish` must not carry a target id;
3. tool actions require an available `(tool, targetId)` pair;
4. an already-attempted pair is rejected as `duplicate_analysis`.

The only model argument a tool ever receives is `{ targetId }`; the backend
resolves it through the target catalog.

## Availability and follow-up targets

`src/graph/availability.ts` computes the action allowlist:

| Target kind                                  | Tools                    |
| -------------------------------------------- | ------------------------ |
| `url`                                        | `analyze_web`            |
| `ip`, `domain`, `email`, `phone`, `username` | `analyze_recon`          |
| `file` classified image                      | `analyze_steg`           |
| `file` classified document                   | `analyze_macro`          |
| `file` classified executable                 | `analyze_malware`        |
| `file` unknown subtype                       | all three file analyzers |
| `unknown`                                    | none                     |

Attempted tool/target pairs are removed from the allowlist, so the model cannot
request the same call twice. An analyzer failure also consumes the pair; failed
analyzers are not retried automatically.

`src/graph/artifacts.ts` extracts URLs, IPv4 addresses and domains from each
pass (raw output, reconstructed Ghidra C-string fragments, and finding evidence),
filters library noise, and promotes them to artifact targets plus indicator
provenance records. This is what enables follow-up passes such as
web → extracted IP → recon. Local file paths from analyzer output are never
promoted to targets.

## Budgets and termination

| Setting                     | Default   | Meaning                                           |
| --------------------------- | --------- | ------------------------------------------------- |
| `passes` query              | 3 (3/4/5) | Analyzer executions requested by the user         |
| `MODEL_MAX_CYCLES`          | 12        | Model decisions per run                           |
| `MODEL_MAX_TOOL_CALLS`      | 20        | Analyzer-tool executions per run                  |
| `TOTAL_ANALYSIS_TIMEOUT_MS` | 600 s     | Whole-run deadline, propagated as an abort signal |

Recorded termination reasons:

| Reason               | Status    | Cause                                         |
| -------------------- | --------- | --------------------------------------------- |
| `model_finished`     | completed | Model returned `finish` with reasoning        |
| `no_artifacts`       | completed | No unattempted tool/target pair remains       |
| `max_passes`         | stopped   | User pass budget reached                      |
| `max_cycles`         | stopped   | Model decision budget reached                 |
| `max_tool_calls`     | stopped   | Tool execution budget reached                 |
| `duplicate_analysis` | stopped   | Model requested an attempted pair             |
| `unsupported_input`  | failed    | No tool accepts the input                     |
| `fatal_error`        | failed    | Model contract failure or invalid tool output |

`termination.detail` records the model's finish reasoning or the budget/error
explanation. Every decision is also logged with run id, pass, tool, target id and
reasoning.

## Prompt contents

`src/prompts/decision.ts` sends only validated state:

- trusted run facts: input type, source kind, MIME, deterministic
  classification, counters and budgets;
- the trusted target id catalog (`id | kind | origin | MIME`) and the trusted
  action allowlist (`tool | target id`);
- trusted tool-history aggregates (status, risk, finding count);
- one `<untrusted_evidence>` block containing target labels, indicators,
  per-pass summaries, latest findings and tool error text;
- remaining pass/cycle/tool budgets and the stop conditions.

Step 9 moved prompt construction into `src/prompts/`. Target display names and
tool errors are JSON-encoded inside the untrusted block, not in the trusted
allowlist. Full raw outputs remain outside state and prompts behind
`RawOutputRef`.

The provider schema uses `targetId: string | null` as a required property because
OpenAI-compatible strict structured-output modes require every property to be in
`required`: actions carry an id, `finish` carries `null`.

## Tests

`tests/analysis-loop.test.ts` covers:

- deterministic first pass with no model call;
- target-compatible tool exposure and enum narrowing;
- artifact extraction and model-selected follow-up (web → extracted IP → recon);
- finish/no-op decisions;
- repeated tool/target rejection;
- max-cycle and max-pass termination;
- analyzer execution failure without crashing the graph;
- unsupported input with no model call.

`tests/classifier.test.ts` covers string and file rules, magic-byte detection,
target construction and input-length validation.

`tests/graph-state.test.ts` continues to validate the complete state snapshot,
now including `pendingAction` and optional decision reasoning on tool history.

Current suite: **110 passed, 7 skipped** (2 OpenRouter live, 5 analyzer live).

## Deliberate limits

- Unknown **files** expose all file analyzers; there is no model-based
  classification fallback yet (Step 9 prompt work).
- Tool execution is sequential by design; no parallel analyzer calls.
- SSRF checks for URLs/domains are wired in Step 10.
- The HTTP runner and report generation remain unwired until Steps 8/10; this
  step exposes `runAnalysisLoop()` for the runner to call.
