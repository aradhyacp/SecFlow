import {
  AIMessage,
  HumanMessage,
  SystemMessage,
  ToolMessage,
} from "@langchain/core/messages";
import { describe, expect, it } from "vitest";

import { fromModelDecision, toModelMessages } from "../src/graph/messages.js";
import { finishDecision, toolCallDecision } from "./helpers/scriptedModel.js";

describe("message adapter", () => {
  it("translates a full LangGraph history into AI SDK messages", () => {
    const messages = toModelMessages([
      new SystemMessage("system rules"),
      new HumanMessage("check example.com"),
      new AIMessage({
        content: "Looking it up.",
        tool_calls: [{ id: "call_1", name: "lookup", args: { target: "example.com" } }],
      }),
      new ToolMessage({
        content: JSON.stringify({ riskScore: 5 }),
        tool_call_id: "call_1",
        name: "lookup",
      }),
    ]);

    expect(messages[0]).toEqual({ role: "system", content: "system rules" });
    expect(messages[1]).toEqual({ role: "user", content: "check example.com" });
    expect(messages[2]).toEqual({
      role: "assistant",
      content: [
        { type: "text", text: "Looking it up." },
        {
          type: "tool-call",
          toolCallId: "call_1",
          toolName: "lookup",
          input: { target: "example.com" },
        },
      ],
    });
    expect(messages[3]).toEqual({
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "call_1",
          toolName: "lookup",
          output: { type: "json", value: { riskScore: 5 } },
        },
      ],
    });
  });

  it("preserves non-JSON tool output as text", () => {
    const [message] = toModelMessages([
      new ToolMessage({ content: "plain failure text", tool_call_id: "call_2", name: "lookup" }),
    ]);

    expect(message).toEqual({
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "call_2",
          toolName: "lookup",
          output: { type: "text", value: "plain failure text" },
        },
      ],
    });
  });

  it("translates provider decisions into AI messages with tool calls", () => {
    const decision = toolCallDecision("lookup", { target: "example.com" }, "call_9");
    const message = fromModelDecision(decision);

    expect(message).toBeInstanceOf(AIMessage);
    expect(message.tool_calls).toEqual([
      { id: "call_9", name: "lookup", args: { target: "example.com" } },
    ]);
  });

  it("keeps text-only decisions free of tool calls", () => {
    const message = fromModelDecision(finishDecision("finished"));

    expect(message).toBeInstanceOf(AIMessage);
    expect(message.tool_calls).toEqual([]);
    expect(message.content).toBe("finished");
  });

  it("wraps non-object tool arguments so validation can reject them", () => {
    const decision = toolCallDecision("lookup", "not-an-object", "call_10");
    const message = fromModelDecision(decision);

    expect(message.tool_calls?.[0]?.args).toEqual({ value: "not-an-object" });
  });
});
