import type { LanguageModelV4GenerateResult } from "@ai-sdk/provider";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import { describe, expect, it } from "vitest";

import { createLogger } from "../src/logger.js";
import { loadConfig } from "../src/config.js";
import { OpenRouterModelClient } from "../src/model/client.js";
import { createModelClient, openRouterModelFactory } from "../src/model/provider.js";
import { ModelContractError } from "../src/http/errors.js";

const logger = createLogger(loadConfig({ NODE_ENV: "test" }));

function mockResult(
  content: LanguageModelV4GenerateResult["content"],
  finishReason: LanguageModelV4GenerateResult["finishReason"] = { unified: "stop", raw: "stop" },
): LanguageModelV4GenerateResult {
  return {
    content,
    finishReason,
    usage: {
      inputTokens: { total: 11, noCache: 11, cacheRead: 0, cacheWrite: 0 },
      outputTokens: { total: 7, text: 7, reasoning: 0 },
    },
    warnings: [],
  };
}

function makeClient(model: MockLanguageModelV4): OpenRouterModelClient {
  return new OpenRouterModelClient({
    model,
    modelId: "mock/model",
    temperature: 0.1,
    maxTokens: 512,
    timeoutMs: 5_000,
    maxRetries: 0,
    logger,
  });
}

describe("OpenRouterModelClient.decide", () => {
  it("maps AI SDK tool calls into the model-independent shape", async () => {
    const model = new MockLanguageModelV4({
      doGenerate: mockResult(
        [
          {
            type: "tool-call",
            toolCallId: "call-1",
            toolName: "echo",
            input: JSON.stringify({ value: "hello" }),
          },
        ],
        { unified: "tool-calls", raw: "tool_calls" },
      ),
    });

    const client = makeClient(model);
    const decision = await client.decide({
      system: "system prompt",
      messages: [{ role: "user", content: "call the tool" }],
      tools: {
        echo: {
          description: "Echo the input",
          inputSchema: z.object({ value: z.string() }),
        },
      },
    });

    expect(decision.toolCalls).toEqual([
      { toolCallId: "call-1", toolName: "echo", input: { value: "hello" } },
    ]);
    expect(decision.finishReason).toBe("tool-calls");
    expect(decision.usage).toEqual({ inputTokens: 11, outputTokens: 7, totalTokens: 18 });

    expect(model.doGenerateCalls).toHaveLength(1);
    const call = model.doGenerateCalls[0];
    expect(call?.temperature).toBe(0.1);
    expect(call?.maxOutputTokens).toBe(512);
    expect(call?.tools?.map((tool) => tool.name)).toContain("echo");
  });

  it("returns text-only decisions unchanged", async () => {
    const model = new MockLanguageModelV4({
      doGenerate: mockResult([{ type: "text", text: "nothing left to analyse" }]),
    });

    const decision = await makeClient(model).decide({
      messages: [{ role: "user", content: "decide" }],
    });

    expect(decision.toolCalls).toEqual([]);
    expect(decision.text).toBe("nothing left to analyse");
    expect(decision.finishReason).toBe("stop");
  });

  it("passes an abort signal so model calls are bounded", async () => {
    const model = new MockLanguageModelV4({
      doGenerate: mockResult([{ type: "text", text: "ok" }]),
    });

    await makeClient(model).decide({ messages: [{ role: "user", content: "go" }] });

    const signal = model.doGenerateCalls[0]?.abortSignal;
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(signal?.aborted).toBe(false);
  });
});

describe("OpenRouterModelClient.generateObject", () => {
  it("returns schema-validated objects", async () => {
    const model = new MockLanguageModelV4({
      doGenerate: mockResult([{ type: "text", text: '{"verdict":"finish","reason":"done"}' }]),
    });

    const object = await makeClient(model).generateObject({
      prompt: "decide",
      schema: z.object({
        verdict: z.enum(["finish", "continue"]),
        reason: z.string(),
      }),
    });

    expect(object).toEqual({ verdict: "finish", reason: "done" });
  });

  it("wraps malformed output in ModelContractError", async () => {
    const model = new MockLanguageModelV4({
      doGenerate: mockResult([{ type: "text", text: "not json" }]),
    });

    await expect(
      makeClient(model).generateObject({
        prompt: "decide",
        schema: z.object({ verdict: z.enum(["finish", "continue"]) }),
      }),
    ).rejects.toBeInstanceOf(ModelContractError);
  });
});

describe("createModelClient", () => {
  it("requires OPENROUTER_API_KEY", () => {
    const config = loadConfig({ NODE_ENV: "test" });
    expect(() => createModelClient(config, logger)).toThrow(/OPENROUTER_API_KEY/);
  });

  it("builds the OpenRouter model from configuration", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      OPENROUTER_API_KEY: "test-key",
      OPENROUTER_MODEL: "openai/gpt-4.1-mini",
      MODEL_TEMPERATURE: "0.2",
      MODEL_MAX_TOKENS: "1024",
      MODEL_TIMEOUT_MS: "1234",
    });

    const client = createModelClient(config, logger);
    expect(client.modelId).toBe("openai/gpt-4.1-mini");
    expect(client.model).toBeDefined();
    expect(openRouterModelFactory.createModel(config).modelId).toBe("openai/gpt-4.1-mini");
  });

  it("honours an injected model factory", () => {
    const config = loadConfig({ NODE_ENV: "test", OPENROUTER_API_KEY: "test-key" });
    const mock = new MockLanguageModelV4({
      doGenerate: mockResult([{ type: "text", text: "ok" }]),
    });

    const client = createModelClient(config, logger, {
      createModel: () => ({ model: mock, modelId: "injected/model" }),
    });

    expect(client.modelId).toBe("injected/model");
    expect(client.model).toBe(mock);
  });
});
