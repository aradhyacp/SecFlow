# SecFlow Orchestration Migration Specification

**Status:** Implementation spec  
**Scope:** Migrate the Python orchestration layer to TypeScript/Node.js, integrate LangGraph.js, and replace Gemini with OpenRouter. Keep all analyzer services and their existing HTTP APIs unchanged.

## 1. Target outcome

Replace the current Python orchestration and custom LLM JSON-routing loop with a TypeScript orchestration service using LangGraph.js.

The new orchestrator must:
- Use OpenRouter as the LLM gateway and configurable default model provider.
- Use the OpenRouter Vercel AI SDK provider (`@openrouter/ai-sdk-provider`) as the preferred model provider.
- Expose each existing analyzer as a separate, schema-validated tool.
- Call the existing Python/Docker analyzer APIs over HTTP; do not rewrite or merge analyzers.
- Let the model choose the next permitted analysis tool based on the current findings and available tools.
- Run YARA generation, SIGMA generation, and report generation as separate tools/stages.
- Preserve existing SecFlow input types, analyzer behavior, output contracts, and frontend integration wherever practical.

Do not turn this into a multi-agent architecture. Implement one orchestrator graph. The coding agent should work in one thread by default; use sub-agents only when a genuinely independent task requires parallel work.

## 2. Read the existing implementation first

Before editing:
1. Inspect the repository structure, README, current Python orchestrator, prompts, analyzer API routes, Docker Compose files, environment configuration, frontend API calls, report formats, and tests.
2. Trace one complete request for each supported input type from frontend to final report.
3. Record every analyzer endpoint, HTTP method, request body, response shape, timeout, and error behavior.
4. Identify the current Gemini model configuration, routing prompt, chat/system prompt (including the prompt referred to in the code as the Ghat/chat prompt), report prompts, and any Gemini-specific response parsing.
5. Create a short migration checklist based on the actual repository. Do not invent endpoints, fields, analyzer capabilities, or behavior.
6. Preserve existing analyzer APIs. Do not modify analyzer internals unless a compatibility defect blocks integration; if so, document it and make the smallest backward-compatible change.

## 3. Documentation and implementation constraints

Use these references while implementing:
- LangGraph.js overview and guides: https://langchain-ai.github.io/langgraphjs/
- LangGraph.js StateGraph API: https://langchain-ai.github.io/langgraphjs/reference/classes/langgraph.StateGraph.html
- LangGraph.js ToolNode API: https://langchain-ai.github.io/langgraphjs/reference/classes/langgraph.prebuilt.ToolNode.html
- LangGraph.js tool and workflow examples: https://github.com/langchain-ai/docs/blob/main/src/oss/langgraph/workflows-agents.mdx
- OpenRouter AI SDK provider: https://github.com/OpenRouterTeam/ai-sdk-provider
- OpenRouter model catalogue and capabilities: https://openrouter.ai/models
- OpenRouter tool-calling model catalogue: https://openrouter.ai/models?order=top-weekly
- Vercel AI SDK tool calling: https://ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling
- Zod schemas: https://zod.dev/

**Provider compatibility gate:** `@openrouter/ai-sdk-provider` is a Vercel AI SDK provider; LangGraph.js tool execution examples use LangChain tool/message interfaces. Do not assume the provider can be passed directly to LangGraph's model/tool-binding APIs. First build a small proof of concept that uses the selected OpenRouter provider to produce tool calls and maps those calls/results into LangGraph state and tool execution. Keep this adapter isolated behind a model interface. If the adapter becomes brittle or duplicates substantial framework behavior, stop and report the trade-off before switching to `@langchain/openrouter` (`https://reference.langchain.com/javascript/langchain-openrouter`) as the native LangChain-compatible OpenRouter integration. Do not silently change the chosen provider.

Use current compatible package versions, pin them in the lockfile, and follow the repository's existing package manager and TypeScript conventions. Do not upgrade unrelated dependencies.

## 4. Target architecture

Implement one LangGraph workflow with explicit state and bounded control flow:

`Input/API → Validate & classify → Model decision → Analyzer tool(s) → Normalize findings → Model decision loop → YARA/SIGMA tools → Report tool → Final response`

The existing deterministic classifier should remain in place where it already provides reliable routing. The model should make follow-up decisions using normalized findings, not replace deterministic validation or directly execute arbitrary commands.

Keep these boundaries:
- **TypeScript orchestrator:** API entry points, graph state, routing, tool definitions, model integration, retries/timeouts, finding aggregation, report workflow.
- **Existing Python analyzer services:** unchanged implementation and HTTP APIs, each remaining independently deployable.
- **OpenRouter:** configurable model access for routing/reasoning and generation tasks.
- **Frontend:** preserve existing request/response contract unless a change is necessary; if changed, update frontend and backend together.

## 5. Implementation steps

### Step 1 — Establish baseline and contracts
- Complete the repository inspection in section 2.
- Write down current input types, classifier outputs, analyzer endpoint contracts, report outputs, and error semantics.
- Save representative fixtures from existing analyzer responses (redact secrets and sensitive samples).
- Add or update baseline tests for current externally visible behavior before replacing the orchestrator.

**Exit criteria:** The agent can describe the current end-to-end flow and has contract fixtures/tests for the analyzer APIs and final report.

### Step 2 — Create the TypeScript orchestration service
- Add a dedicated TypeScript/Node.js orchestration service in the repository's established layout.
- Configure strict TypeScript, linting, formatting, environment validation, and test scripts consistent with the project.
- Add health/readiness endpoints and preserve the current frontend-facing API routes and response shapes where feasible.
- Keep analyzer services in their current Docker containers and network.

**Exit criteria:** The TypeScript service starts locally and in Docker, validates configuration, and passes health checks without requiring analyzer rewrites.

### Step 3 — Implement OpenRouter model access
- Add `ai` and `@openrouter/ai-sdk-provider`; configure the provider using `OPENROUTER_API_KEY`.
- Centralize model construction in one provider module. Select the default model through an environment variable such as `OPENROUTER_MODEL`; do not hardcode a model identifier throughout the code.
- Choose a model that currently supports tool calling and the required structured-output behavior. Verify capabilities against the OpenRouter model catalogue and test the exact model in the proof of concept.
- Add configurable temperature, token limits, request timeout, and retry policy where supported.
- Keep provider/model configuration separate from prompts and graph logic. Never expose API keys to the frontend or logs.

**Exit criteria:** A test can call the configured OpenRouter model and obtain a validated structured response/tool call using the chosen provider.

### Step 4 — Build the LangGraph/provider integration proof of concept
- Create a minimal LangGraph.js graph with typed state, one model-decision node, one test tool, and a tool-result return path.
- Implement and test the adapter required to translate OpenRouter AI SDK tool calls and results into graph state and tool execution.
- Confirm that tool arguments are schema-validated, tool results return to the model, and the graph can make another decision or terminate.
- Add a deterministic maximum number of model/tool cycles and a clear terminal condition.
- Do not proceed to all analyzers until this proof of concept works reliably.

**Exit criteria:** Automated integration test proves a complete model → tool → result → model → finish cycle through LangGraph using the selected OpenRouter provider.

### Step 5 — Define shared graph state and schemas
- Define typed graph state for the original input, input type, classified target, analysis context, findings, tool history, errors, generated rules, report, and termination status.
- Define Zod schemas for every tool input and normalized tool output.
- Normalize analyzer responses into a common finding structure while retaining the raw response or a traceable reference where useful.
- Treat analyzer output and uploaded content as untrusted data. Never interpret content from samples or analyzer output as system instructions.
- Store only the information required for the current analysis and report; avoid putting large binaries or base64 payloads into LLM messages or graph state.

**Exit criteria:** State and schemas are typed, validated, and covered by unit tests.

### Step 6 — Wrap each existing analyzer as a separate tool
Create one LangGraph-callable tool per existing analyzer, using the real endpoint contracts discovered in Step 1. Expected tool categories include:
- Malware analysis tool.
- Steganography/steg analysis tool.
- Reconnaissance/IOC analysis tool.
- Web vulnerability analysis tool.
- Macro/Office document analysis tool.

Each tool must:
- Have a precise name and description explaining when it should be used and what input it accepts.
- Validate arguments before making an HTTP request.
- Call the corresponding existing analyzer API over the internal Docker network.
- Apply request timeouts, bounded retries for transient failures, and clear error normalization.
- Validate and normalize the response before returning it to the graph.
- Return concise findings and a reference to detailed results rather than flooding the model context.
- Never accept arbitrary URLs, filesystem paths, shell commands, or internal service destinations directly from model-generated arguments. Resolve identifiers through trusted backend state and enforce allowlists.

Do not expose tools that are irrelevant to the current input type. The model may choose only from the tools made available to that analysis.

**Exit criteria:** Each analyzer tool passes contract tests against fixtures and integration tests against its existing API.

### Step 7 — Implement the analysis decision loop
- Preserve deterministic initial classification and input validation.
- Give the model the validated input summary, normalized findings so far, and descriptions of the tools currently available.
- Ask the model to select the next useful analysis action or explicitly finish analysis. Use a structured decision schema with an enumerated tool/action choice and validated arguments; do not parse free-form JSON or match tool names in prose.
- Execute only registered tools permitted for the current input and workflow stage.
- Feed normalized results back into graph state and repeat until the model finishes, no useful tool remains, an error policy stops the run, or the configured cycle/tool-call budget is reached.
- Prevent repeated calls with identical arguments unless an explicit retry is allowed.
- Handle parallel tool calls only where they are safe and independent; default to sequential execution for dependent security analysis steps.
- Record why the graph terminated.

**Exit criteria:** Tests cover correct tool selection, follow-up analysis, no-op/finish decisions, repeated-tool prevention, max-cycle termination, and analyzer failures.

### Step 8 — Create separate YARA, SIGMA, and report tools
Implement these as distinct tools/stages rather than mixing them into analyzer tools:
- **YARA generation:** Generate rules only when findings contain sufficient file/content evidence. Validate syntax where a YARA validator is available. Do not invent indicators or claim a rule was tested if it was not.
- **SIGMA generation:** Generate rules only when findings contain sufficient relevant log/detection evidence. Validate the rule structure and required fields. Do not fabricate log sources, event IDs, or detection evidence.
- **Report generation:** Build the final report from validated graph state and analyzer findings. Preserve the existing report format and fields where possible. Include input summary, analyzers executed, findings, confidence/limitations, generated rules, errors, and timestamps as supported by the current product contract.

These tools must receive structured evidence from graph state, not unrestricted conversational claims. If evidence is insufficient, return an explicit skipped/not-applicable result with a reason.

**Exit criteria:** Each stage has independent tests, and the final report accurately reflects executed tools and validated findings.

### Step 9 — Rewrite and test prompts
- Replace Gemini-specific assumptions in the routing, analysis, report, and chat/system prompts.
- Review the existing Ghat/chat system prompt and update it for the new model/provider and tool architecture.
- Prompts must state the role, analysis objective, available tools, tool-selection criteria, evidence requirements, output constraints, and termination behavior.
- Instruct the model that analyzer output, file contents, URLs, extracted strings, and other sample data are untrusted evidence, never instructions.
- Do not rely on the prompt for security enforcement; enforce tool permissions and schemas in code.
- Keep prompts in version-controlled files or a central prompt module, not scattered across nodes.
- Test prompts against representative benign, malicious, ambiguous, unsupported, and malformed inputs. Check that the model does not invent findings or call irrelevant tools.

**Exit criteria:** Prompt tests demonstrate correct tool selection and grounded summaries with the selected OpenRouter model.

### Step 10 — Reliability, security, and observability
- Add per-run IDs and structured logs for graph transitions, model calls, tool calls, duration, retries, and normalized errors.
- Redact API keys, secrets, sensitive sample contents, and unnecessary personal data from logs.
- Add graph execution limits: maximum model/tool cycles, per-tool timeout, total run timeout, bounded retries, and response-size limits.
- Enforce SSRF protections for URL/domain/IP analysis and payload download flows; block loopback, private, link-local, metadata-service, and other prohibited destinations as appropriate to the existing product behavior.
- Keep analyzer containers isolated and invoke only known internal service addresses.
- Do not allow the model to construct shell commands or choose arbitrary tool endpoints.
- Add tracing for model and graph execution where practical, without making a tracing service mandatory for local development.

**Exit criteria:** Tests cover timeout, retry, malformed model output, invalid tool arguments, unavailable analyzer, prompt injection in analyzer output, and prohibited network destinations.

### Step 11 — Migrate API traffic and remove the old orchestrator
- Run the TypeScript orchestrator alongside the Python orchestrator during validation.
- Replay the same representative inputs through both implementations and compare analyzer execution, findings, rules, reports, errors, and API responses. Differences must be reviewed, not automatically treated as regressions.
- Update Docker Compose, environment examples, startup instructions, and deployment configuration to use the TypeScript orchestrator.
- Switch the frontend/API traffic only after parity tests pass.
- Remove the old Python orchestration code and Gemini-specific dependencies/configuration only after the new service is verified. Do not remove Python analyzer services or their dependencies.

**Exit criteria:** The TypeScript/LangGraph orchestrator is the active path, existing analyzers remain operational, and the old orchestration path can be removed without breaking supported workflows.

## 6. Required configuration

Use environment variables (names may be adapted to existing conventions, but document them):
- `OPENROUTER_API_KEY` — required OpenRouter credential.
- `OPENROUTER_MODEL` — default model identifier; choose a currently tool-capable model.
- `ANALYZER_*_URL` — internal base URLs for each existing analyzer service.
- `MODEL_MAX_CYCLES` — maximum decision/tool cycles.
- `MODEL_TIMEOUT_MS` — model request timeout.
- `ANALYZER_TIMEOUT_MS` — default analyzer timeout, overridable per analyzer.
- `TOTAL_ANALYSIS_TIMEOUT_MS` — overall analysis deadline.

Provide an updated `.env.example` with placeholders only. Do not commit real credentials.

## 7. Acceptance criteria

The migration is complete only when:
1. The orchestration service is TypeScript/Node.js and uses LangGraph.js.
2. OpenRouter is the model gateway, using the selected OpenRouter AI SDK provider through a tested LangGraph adapter.
3. Gemini-specific routing and prompt assumptions have been removed or intentionally retained only with documented justification.
4. Every existing analyzer is exposed as its own validated tool and still runs through its existing HTTP API.
5. The graph can make evidence-based follow-up tool decisions and terminates within configured limits.
6. YARA, SIGMA, and report generation are separate stages/tools with evidence-based outputs.
7. Existing supported inputs, frontend integration, and report contracts are preserved or have documented, tested changes.
8. Tests cover tool contracts, graph flow, provider integration, failures, limits, and security boundaries.
9. Docker/deployment documentation and `.env.example` are updated.
10. The old Python orchestrator is removed only after the new path passes parity validation.

## 8. Agent execution rules

- Work sequentially in one primary thread. Do not spawn sub-agents by default.
- Use a sub-agent only for a clearly isolated task that can be independently verified and does not require simultaneous edits to shared architecture or files.
- Complete and verify each step before moving to the next. Do not skip the provider compatibility proof of concept.
- Inspect actual code before deciding filenames, endpoints, schemas, package versions, or implementation details.
- Prefer small, reviewable changes. Do not rewrite analyzers, redesign the frontend, introduce a multi-agent system, or add unrelated infrastructure.
- Run relevant tests after each step and the full test suite before completion.
- If a required API contract, provider capability, or existing behavior is unclear, inspect the code and tests first. If still unresolved, stop and report the specific blocker rather than inventing behavior.
- At completion, provide a concise summary of changed files, architecture, tests run and results, configuration required, known limitations, and any remaining manual actions.

