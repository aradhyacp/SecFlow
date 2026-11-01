# Step 4 — LangGraph × OpenRouter proof of concept

**Status:** implemented, automated tests passing, live provider run pending an API key.

## What was built

The provider gate exists to answer one question before any analyzer is wired in:
can the Vercel AI SDK + OpenRouter tool calls be driven by a LangGraph.js graph
without either side fighting the other?

The answer, as implemented:

```
START → decide (ModelClient, one step) → act (ToolRegistry) → decide → … → END
```

- **`decide`** sends the whole LangChain message history to the model as AI SDK
  messages, with the currently registered tools declared but not executable.
  The SDK therefore *returns* tool calls instead of running them.
- **`act`** validates each call against the tool's Zod schema, executes only
  allowlisted tools, appends a `ToolMessage`, and records the execution.
- The conditional edge after `decide` returns to `act` only while the model
  requested tools and the cycle budget allows it. Otherwise it goes to `END`
  with a terminal status of `completed` or `max_cycles`.

This keeps LangChain/LangGraph as the control-flow layer and the AI SDK as the
provider layer, with a small message adapter between them. No framework
duplicates the other's behaviour.

## Packages

| Package | Version | Role |
|---|---|---|
| `@langchain/langgraph` | `^1.6.0` (lockfile `1.6.0`) | `StateGraph`, `Annotation`, `START`/`END` |
| `@langchain/core` | `^1.3.2` (peer) | `BaseMessage`/`AIMessage`/`ToolMessage` state |
| `ai` | `^7.0.159` | AI SDK `generateText`/`tool` types |
| `@openrouter/ai-sdk-provider` | `^3.1.0` | OpenRouter chat provider |

`@langchain/langgraph@1.6.0` accepts `zod ^3.25.32 || ^4.2.0`; the service
already uses Zod 4.

## Modules

| File | Responsibility |
|---|---|
| `src/graph/tools.ts` | `defineTool()` validation wrapper, `ToolRegistry` allowlist, AI SDK tool declarations |
| `src/graph/messages.ts` | LangChain message ↔ AI SDK message translation, decision → `AIMessage` |
| `src/graph/poc/state.ts` | Typed `Annotation.Root` state: messages, cycles, status, final text, usage, executions |
| `src/graph/poc/tool.ts` | `lookup_test_indicator` — synthetic, network-free POC tool |
| `src/graph/poc/graph.ts` | Graph builder + `runPoc()` |

### Safety properties already in place

- Tool names are resolved from the registry; an arbitrary name from the model
  becomes an `unknown_tool` result and is sent back to the model, never run.
- Arguments are parsed with the tool's Zod schema before execution. Invalid
  arguments produce a `validation` error message in the tool result.
- Execution exceptions are converted into tool results, so the graph continues
  and the model can recover.
- The cycle budget is enforced in the `decide` node and mirrored by LangGraph's
  `recursionLimit`.
- Tool results are serialized as JSON when possible; binary/large data is not
  part of this POC.

## Tests

```bash
cd backend/orchestrator-ts
npm run typecheck
npm run lint
npm test
```

Current result: **49 passed, 2 skipped** (the two live OpenRouter tests).

Deterministic coverage:

- full model → tool → result → model → finish cycle, including the tool result
  visible in the second model request;
- schema violation fed back without execution;
- unknown tool rejected and fed back;
- cycle-budget termination with the final tool call left unexecuted;
- immediate finish with no tool call;
- custom registry allowlisting;
- token-usage accumulation;
- message adapter round-trips for text, JSON tool output, plain-text tool
  output, text+tool-call assistant messages, and non-object tool arguments.

The live tests (`tests/integration/openrouter.live.test.ts` and
`tests/integration/langgraph.live.test.ts`) run only when `OPENROUTER_API_KEY`
is set. They verify the structured-output path and the full live graph cycle.

## Exit gate

Step 4's automated test proves the complete cycle with a scripted model. The
remaining exit criterion is the same cycle against the selected OpenRouter
model. It requires a real key:

```bash
OPENROUTER_API_KEY=... npm test
```

Until that passes, do not start wiring real analyzers (Step 6).
