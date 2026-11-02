# Step 8 — YARA, SIGMA, and report stages

**Status:** complete.

Step 8 adds three post-analysis stages as separate tools:

| Tool              | Input | Evidence source                               | Output                                      |
| ----------------- | ----- | --------------------------------------------- | ------------------------------------------- |
| `generate_yara`   | `{}`  | validated graph state (file/content findings) | `RuleGenerationOutput` with YARA artifacts  |
| `generate_sigma`  | `{}`  | validated graph state (network/log findings)  | `RuleGenerationOutput` with SIGMA artifacts |
| `generate_report` | `{}`  | validated graph state + generated rules       | JSON/HTML report files and report state     |

The tools accept no model-supplied paths, URLs, evidence text, or commands. They
read only the trusted `ToolContext.state` snapshot. `finalizeAnalysis()` runs
them in order after the analysis loop and records failures without throwing.

```
analysis loop → finalize:
  generate_yara → generate_sigma → generate_report
```

## Evidence gates

`src/rules/evidence.ts` builds a bounded evidence packet from normalized graph
state. Raw analyzer output is not sent to the rule-generation model.

- YARA requires at least one file/content finding from `malware`, `steg`, or
  `macro`, with concrete evidence (or a content-bearing finding type such as
  `decompilation`, `disassembly`, `macro_source`, `macro_xlm`, or
  `steg_hidden_data`).
- SIGMA requires relevant `web`/`recon` findings, a medium-or-higher finding, or
  a concrete network indicator.
- When a gate is not met, the tool returns `status: "skipped"` with an explicit
  reason and the model is not called.
- Packets are capped at 20 findings / 24,000 characters. Each finding has a
  stable evidence ref such as `macro:pass1:finding2`; every generated rule must
  cite at least one ref that exists in the packet.
- Evidence text is wrapped in the existing `<untrusted_evidence>` contract, and
  the prompt includes `UNTRUSTED_DATA_POLICY`.

## YARA generation and validation

`src/rules/generate.ts` asks the model for 2–5 structured rule drafts. It then:

1. filters `evidence_refs` against the packet and rejects rules with no valid
   ref;
2. compiles each rule with YARA-X (`@virustotal/yara-x`, WebAssembly);
3. checks quoted literals in the `strings:` section against the evidence packet
   so a syntactically valid rule cannot invent an indicator;
4. assigns one of:
   - `valid` — compiled by YARA-X and grounded;
   - `generated` — YARA-X was unavailable, so syntax could not be confirmed;
   - `invalid` — compilation, evidence refs, or grounding failed.

YARA-X initialization failures are reported as `unavailable`, not `invalid`.
Rules are never described as “tested” merely because generation succeeded.

## SIGMA generation and validation

SIGMA drafts are parsed with the `yaml` package and checked for:

- a YAML mapping;
- non-empty `title`;
- UUID `id`;
- `logsource` containing `category`, `product`, or `service`;
- `detection.condition`;
- a valid `level` when present.

Concrete detection values (URLs, IPs, domains, hashes, and executable/document
filenames) are also checked against the evidence packet. A structurally valid
rule that invents an indicator is marked `invalid`. This is structural validation
only; no pySigma backend conversion is performed.

## Report generation

`src/report/build.ts` builds the report structure and findings deterministically
from graph state. An optional narrative model (injected in Step 9) may rewrite
only `summary` and `recommendations`; a model failure falls back to the
deterministic text. The report cannot invent findings. The preserved PWNDoc
fields are:

- `input`, `total_passes`, `overall_risk_score`, `summary`;
- `passes[]` with `pass_number`, `analyzer`, and complete `findings`;
- `recommendations`;
- `threat_intel.yara` / `threat_intel.sigma` in the legacy shapes expected by the
  existing report renderer.

Additional traceability fields are included because the PWNDoc schema allows
extra properties:

- `rules` — every rule artifact, including invalid/skipped status;
- `tools` — executed tool history;
- `errors` — recoverable analysis/report errors;
- `analyzers_executed`, `limitations`, and `timestamps`.

`input` is the safe `source.displayName`, not a temporary filesystem path. This
is a deliberate improvement over the Python report builder, which used the first
analyzer's `input` value (often a temp path).

`src/report/html.ts` renders a self-contained, escaped HTML report with summary,
recommendations, pass findings, evidence, YARA/SIGMA rule text, invalid-rule
details, tool history, errors, and limitations. The visual layout is intentionally
simplified relative to the Python template, but the data and security escaping
are preserved. JSON and HTML are written to
`REPORTS_DIR/<job_id>/report.json` and `report.html`; the job id must be a
16-character lowercase hex value (the runner supplies `sha256(input)[:16]`, with
a hash fallback for tests).

### Report failure policy

- No findings: report status `skipped`, no files written.
- Rule stage failure: recorded as an error; the report is still generated from
  the available evidence.
- Report build/write failure: report status `failed`, with the reason in
  `state.report.error` and `state.errors`.
- The analysis termination reason is never altered by finalization.

## Tests

Independent tests cover:

- YARA-X compilation of valid and malformed rules;
- YARA evidence gating, evidence-ref enforcement, grounding, and model failures;
- SIGMA structure validation, evidence gating, grounding, and malformed YAML;
- report contract validation, legacy `threat_intel` mapping, HTML escaping, and
  skipped reports;
- end-to-end finalization, insufficient-evidence skips, generation failures, no
  findings, and missing generation tools.

Current suite: **145 passed, 9 skipped** (live OpenRouter/analyzer tests remain
gated behind their environment flags).

## Deviations from the Python implementation

1. Report structure/findings are deterministic; Step 9 adds an optional model
   narrative for summary and recommendations with a deterministic fallback. The
   Python reporter asks Groq to enhance similar fields. The report shape and
   recommendation coverage otherwise match the existing contract.
2. The HTML template is a functional, self-contained equivalent rather than a
   byte-for-byte port of the Python CSS/markup.
3. YARA/SIGMA generation and validation are new TS stages; the Python
   orchestrator did not implement them in the current backend.
4. Additional traceability fields are present under the permissive PWNDoc schema.
