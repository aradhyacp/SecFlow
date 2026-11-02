import { describe, expect, it } from "vitest";

import { loadConfig } from "../../src/config.js";
import { buildAvailableActions } from "../../src/graph/availability.js";
import { decisionSchemaFor } from "../../src/graph/decision.js";
import { makeIndicatorId, makeTargetId } from "../../src/graph/ids.js";
import type { SecFlowResult } from "../../src/graph/schema/analyzer.js";
import { createLogger } from "../../src/logger.js";
import { createModelClient } from "../../src/model/provider.js";
import { buildDecisionPrompt, DECISION_SYSTEM_PROMPT } from "../../src/prompts/decision.js";
import { buildReport } from "../../src/report/build.js";
import { enhanceReportNarrative, evidenceForReport } from "../../src/report/narrative.js";
import { makeState } from "../helpers/analysisState.js";

const apiKey = process.env.OPENROUTER_API_KEY;
const describeLive = apiKey ? describe : describe.skip;

/**
 * Live prompt gate (Step 9 exit criterion). This verifies that the selected
 * OpenRouter model follows the tool allowlist for a concrete follow-up action.
 */
describeLive("OpenRouter prompt behavior", () => {
  it("selects the allowed follow-up analyzer from grounded evidence", async () => {
    const base = makeState();
    const primary = {
      ...base.target,
      id: makeTargetId("url", "https://portal.example/login"),
      kind: "url" as const,
      value: "https://portal.example/login",
      displayName: "https://portal.example/login",
      mimeType: "text/html",
    };
    const artifact = {
      ...primary,
      id: makeTargetId("url", "http://recongraph.xyz/payload.exe"),
      value: "http://recongraph.xyz/payload.exe",
      displayName: "http://recongraph.xyz/payload.exe",
      origin: "artifact" as const,
    };
    const webPass: SecFlowResult = {
      analyzer: "web",
      pass: 1,
      input: primary.displayName,
      findings: [
        {
          type: "payload_url",
          detail: "The page references a suspicious payload URL: http://recongraph.xyz/payload.exe",
          severity: "high",
          evidence: "http://recongraph.xyz/payload.exe",
        },
      ],
      risk_score: 8,
      raw_output: "synthetic live-prompt fixture",
    };
    const state = makeState(
      {
        source: { kind: "target", displayName: primary.displayName },
        target: primary,
        targets: [primary, artifact],
        inputType: "url",
        classification: {
          inputType: "url",
          analyzer: "web",
          mimeType: "text/html",
          magicOutput: "URL string",
          deterministic: true,
        },
        indicators: [
          {
            id: makeIndicatorId("url", artifact.value),
            kind: "url",
            value: artifact.value,
            sourceAnalyzer: "web",
            sourcePass: 1,
            confidence: 0.8,
          },
        ],
        toolHistory: [
          {
            id: "tool_0000000000000001",
            pass: 1,
            tool: "analyze_web",
            targetId: primary.id,
            status: "succeeded",
            startedAt: "2026-11-01T00:00:00.000Z",
            durationMs: 10,
            findingCount: 1,
            riskScore: 8,
            summary: "web completed",
          },
        ],
        termination: null,
        counters: { passes: 1, cycles: 1, toolCalls: 1, duplicateRejections: 0 },
      },
      [webPass],
    );
    const available = buildAvailableActions({
      targets: state.targets,
      classification: state.classification,
      primaryTargetId: primary.id,
      registeredTools: ["analyze_web"],
      history: state.toolHistory,
    });
    expect(available).toEqual([{ tool: "analyze_web", targetId: artifact.id }]);

    const config = loadConfig({
      NODE_ENV: "test",
      OPENROUTER_API_KEY: apiKey,
      OPENROUTER_MODEL: process.env.OPENROUTER_MODEL ?? "nvidia/nemotron-3-ultra-550b-a55b:free",
      MODEL_TIMEOUT_MS: "60000",
      MODEL_MAX_RETRIES: "1",
    });
    const client = createModelClient(config, createLogger(config));
    const result = await client.generateObject({
      system: DECISION_SYSTEM_PROMPT,
      prompt: buildDecisionPrompt({
        state,
        available,
        toolDescriptions: {
          analyze_web: "Analyze a URL for vulnerabilities and security misconfigurations.",
        },
        maxPasses: 3,
        maxCycles: 12,
        maxToolCalls: 20,
      }),
      schema: decisionSchemaFor(["analyze_web"]),
      temperature: 0,
      maxOutputTokens: 300,
    });

    expect(result.action).toBe("analyze_web");
    expect(result.targetId).toBe(artifact.id);
    expect(result.reasoning.length).toBeGreaterThan(0);
  }, 90_000);

  it("writes a grounded report narrative from validated state", async () => {
    const state = makeState();
    const report = buildReport(state, "2026-11-01T00:06:00.000Z");
    expect(evidenceForReport(state, report)).toContain("<untrusted_evidence");
    const config = loadConfig({
      NODE_ENV: "test",
      OPENROUTER_API_KEY: apiKey,
      OPENROUTER_MODEL: process.env.OPENROUTER_MODEL ?? "nvidia/nemotron-3-ultra-550b-a55b:free",
      MODEL_TIMEOUT_MS: "60000",
      MODEL_MAX_RETRIES: "1",
    });
    const client = createModelClient(config, createLogger(config));

    const narrative = await enhanceReportNarrative(state, report, client);

    expect(narrative.summary.length).toBeGreaterThan(20);
    expect(narrative.summary).not.toContain("/tmp/");
    expect(narrative.recommendations.length).toBeGreaterThan(0);
    expect(narrative.recommendations.every((item) => item.length > 5)).toBe(true);
  }, 90_000);
});
