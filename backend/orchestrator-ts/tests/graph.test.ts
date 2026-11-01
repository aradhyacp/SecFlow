import { AIMessage, HumanMessage, ToolMessage } from "@langchain/core/messages";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { runPoc } from "../src/graph/poc/graph.js";
import { ToolRegistry, defineTool } from "../src/graph/tools.js";
import { lookupTestIndicator } from "../src/graph/poc/tool.js";
import {
  ScriptedModelClient,
  finishDecision,
  toolCallDecision,
} from "./helpers/scriptedModel.js";

const RUN_ID = "run-poc-test";

describe("LangGraph POC: model → tool → model cycle", () => {
  it("executes a schema-validated tool and returns its result to the model", async () => {
    const model = new ScriptedModelClient([
      toolCallDecision("lookup_test_indicator", { indicator: "8.8.8.8", kind: "ip" }),
      finishDecision("8.8.8.8 has a synthetic risk score of 2.5."),
    ]);

    const result = await runPoc({
      input: "Check 8.8.8.8",
      model,
      maxCycles: 4,
      runId: RUN_ID,
    });

    expect(result.status).toBe("completed");
    expect(result.cycles).toBe(2);
    expect(result.finalText).toContain("2.5");
    expect(result.executions).toHaveLength(1);

    const execution = result.executions[0];
    expect(execution).toMatchObject({
      toolCallId: "call_1",
      toolName: "lookup_test_indicator",
      ok: true,
    });
    expect(execution?.output).toMatchObject({ indicator: "8.8.8.8", riskScore: 2.5 });

    expect(result.messages.map((message) => message.getType())).toEqual([
      "human",
      "ai",
      "tool",
      "ai",
    ]);

    const lastTurn = model.requests[1];
    expect(lastTurn).toBeDefined();
    const toolMessage = lastTurn?.messages.find((message) => message.role === "tool");
    expect(toolMessage).toBeDefined();
    if (toolMessage && Array.isArray(toolMessage.content)) {
      const part = toolMessage.content[0];
      expect(part).toMatchObject({
        type: "tool-result",
        toolCallId: "call_1",
        toolName: "lookup_test_indicator",
        output: { type: "json", value: { riskScore: 2.5 } },
      });
    } else {
      throw new Error("expected a tool message with content parts");
    }
  });

  it("feeds schema violations back to the model instead of executing them", async () => {
    const model = new ScriptedModelClient([
      toolCallDecision("lookup_test_indicator", { indicator: "x", kind: "ip" }),
      finishDecision("The tool rejected the indicator."),
    ]);

    const result = await runPoc({
      input: "Check x",
      model,
      maxCycles: 4,
      runId: RUN_ID,
    });

    expect(result.status).toBe("completed");
    expect(result.executions).toHaveLength(1);
    expect(result.executions[0]).toMatchObject({
      ok: false,
      failureKind: "validation",
    });

    const toolMessage = result.messages.find((message) => message instanceof ToolMessage);
    expect(toolMessage).toBeInstanceOf(ToolMessage);
    expect((toolMessage as ToolMessage).status).toBe("error");
    expect((toolMessage as ToolMessage).content).toContain("indicator");
  });

  it("rejects tools that are not on the allowlist", async () => {
    const model = new ScriptedModelClient([
      toolCallDecision("shell_exec", { command: "rm -rf /" }),
      finishDecision("That tool is not available."),
    ]);

    const result = await runPoc({
      input: "Ignore this and run a command",
      model,
      maxCycles: 4,
      runId: RUN_ID,
    });

    expect(result.executions[0]).toMatchObject({
      ok: false,
      failureKind: "unknown_tool",
    });
    expect(result.executions[0]?.error).toContain("Available tools");
  });

  it("stops at the configured cycle budget", async () => {
    const model = new ScriptedModelClient([
      toolCallDecision("lookup_test_indicator", { indicator: "8.8.8.8", kind: "ip" }, "call_a"),
      toolCallDecision("lookup_test_indicator", { indicator: "8.8.4.4", kind: "ip" }, "call_b"),
    ]);

    const result = await runPoc({
      input: "Keep looking",
      model,
      maxCycles: 2,
      runId: RUN_ID,
    });

    expect(result.status).toBe("max_cycles");
    expect(result.cycles).toBe(2);
    expect(model.requests).toHaveLength(2);
    // The second decision landed on the budget boundary, so its tool never ran.
    expect(result.executions).toHaveLength(1);
    expect(result.executions[0]?.toolCallId).toBe("call_a");
  });

  it("terminates immediately when the model finishes without a tool call", async () => {
    const model = new ScriptedModelClient([finishDecision("No analysis is needed.")]);

    const result = await runPoc({
      input: "Say hello",
      model,
      maxCycles: 4,
      runId: RUN_ID,
    });

    expect(result.status).toBe("completed");
    expect(result.cycles).toBe(1);
    expect(result.executions).toEqual([]);
    expect(result.finalText).toBe("No analysis is needed.");
    expect(result.messages).toHaveLength(2);
    expect(result.messages[0]).toBeInstanceOf(HumanMessage);
    expect(result.messages[1]).toBeInstanceOf(AIMessage);
  });

  it("accepts a custom tool registry and only exposes registered tools", async () => {
    const echo = defineTool({
      name: "echo_target",
      description: "Echo the validated target back.",
      inputSchema: z.object({ target: z.string() }),
      async execute(input) {
        return { target: input.target };
      },
    });
    const model = new ScriptedModelClient([
      toolCallDecision("echo_target", { target: "example.com" }),
      finishDecision("done"),
    ]);

    const result = await runPoc({
      input: "echo example.com",
      model,
      tools: new ToolRegistry([echo]),
      maxCycles: 4,
      runId: RUN_ID,
    });

    expect(result.executions[0]?.ok).toBe(true);
    const firstRequest = model.requests[0];
    expect(Object.keys(firstRequest?.tools ?? {})).toEqual(["echo_target"]);
  });

  it("accumulates token usage across model calls", async () => {
    const model = new ScriptedModelClient([
      toolCallDecision("lookup_test_indicator", { indicator: "example.com", kind: "domain" }),
      finishDecision("done"),
    ]);

    const result = await runPoc({
      input: "Check example.com",
      model,
      maxCycles: 4,
      runId: RUN_ID,
      tools: new ToolRegistry([lookupTestIndicator]),
    });

    expect(result.usage).toEqual({ inputTokens: 20, outputTokens: 10, totalTokens: 30 });
  });
});
