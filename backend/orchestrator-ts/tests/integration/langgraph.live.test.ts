import { describe, expect, it } from "vitest";

import { loadConfig } from "../../src/config.js";
import { createLogger } from "../../src/logger.js";
import { createModelClient } from "../../src/model/provider.js";
import { DEFAULT_POC_SYSTEM_PROMPT, runPoc } from "../../src/graph/poc/graph.js";

const apiKey = process.env.OPENROUTER_API_KEY;
const describeLive = apiKey ? describe : describe.skip;

/**
 * Step 4 exit gate. Runs only when OPENROUTER_API_KEY is present:
 *
 *   OPENROUTER_API_KEY=... npm test
 */
describeLive("LangGraph + OpenRouter live cycle", () => {
  it("completes model → tool → model → finish through the graph", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      OPENROUTER_API_KEY: apiKey,
      OPENROUTER_MODEL: process.env.OPENROUTER_MODEL ?? "nvidia/nemotron-3-ultra-550b-a55b:free",
      MODEL_TIMEOUT_MS: "60000",
      MODEL_MAX_RETRIES: "1",
    });
    const client = createModelClient(config, createLogger(config));

    const result = await runPoc({
      input:
        "Use the lookup_test_indicator tool for indicator 8.8.8.8 (kind ip), then summarize its synthetic verdict.",
      model: client,
      maxCycles: 4,
      runId: "live-langgraph-poc",
      systemPrompt: `${DEFAULT_POC_SYSTEM_PROMPT}
You must call lookup_test_indicator exactly once before answering.`,
    });

    expect(result.status).toBe("completed");
    expect(result.cycles).toBeGreaterThanOrEqual(2);
    expect(result.executions.length).toBeGreaterThanOrEqual(1);
    expect(result.executions[0]).toMatchObject({
      toolName: "lookup_test_indicator",
      ok: true,
    });
    expect(result.finalText.length).toBeGreaterThan(0);
  }, 120_000);
});
