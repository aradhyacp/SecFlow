import {
  AIMessage,
  HumanMessage,
  SystemMessage,
  ToolMessage,
  type BaseMessage,
} from "@langchain/core/messages";
import type {
  AssistantContent,
  JSONValue,
  ModelMessage,
  ToolResultPart,
} from "ai";

import type { ModelDecision } from "../model/types.js";

type MessageContent = BaseMessage["content"];

function textFromContent(content: MessageContent): string {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === "string") {
          return part;
        }
        if (part && typeof part === "object" && "text" in part && typeof part.text === "string") {
          return part.text;
        }
        return "";
      })
      .join("");
  }
  return "";
}

function toToolCallArgs(input: unknown): Record<string, unknown> {
  if (input && typeof input === "object" && !Array.isArray(input)) {
    return input as Record<string, unknown>;
  }
  // Non-object arguments are preserved so schema validation can reject them
  // with a useful message instead of the adapter silently inventing a shape.
  return { value: input };
}

function toToolResultPart(message: ToolMessage): ToolResultPart {
  const text = textFromContent(message.content);
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }

  return {
    type: "tool-result",
    toolCallId: message.tool_call_id,
    toolName: message.name ?? "unknown",
    output:
      json !== undefined && json !== null && typeof json === "object"
        ? { type: "json", value: json as JSONValue }
        : { type: "text", value: text },
  };
}

/**
 * Translate LangGraph's LangChain message state into the Vercel AI SDK prompt
 * format consumed by the OpenRouter provider.
 */
export function toModelMessages(messages: BaseMessage[]): ModelMessage[] {
  return messages.map((message): ModelMessage => {
    if (message instanceof SystemMessage) {
      return { role: "system", content: textFromContent(message.content) };
    }

    if (message instanceof HumanMessage) {
      return { role: "user", content: textFromContent(message.content) };
    }

    if (message instanceof ToolMessage) {
      return { role: "tool", content: [toToolResultPart(message)] };
    }

    if (message instanceof AIMessage) {
      const text = textFromContent(message.content);
      const toolCalls = message.tool_calls ?? [];

      if (toolCalls.length === 0) {
        return { role: "assistant", content: text };
      }

      const content: AssistantContent = [];
      if (text.length > 0) {
        content.push({ type: "text", text });
      }
      for (const call of toolCalls) {
        content.push({
          type: "tool-call",
          toolCallId: call.id ?? "",
          toolName: call.name,
          input: call.args,
        });
      }
      return { role: "assistant", content };
    }

    return { role: "user", content: textFromContent(message.content) };
  });
}

/**
 * Turn a provider tool-call decision into an AI message the graph can route on
 * and later translate back to the provider as assistant history.
 */
export function fromModelDecision(decision: ModelDecision): AIMessage {
  return new AIMessage({
    content: decision.text,
    tool_calls: decision.toolCalls.map((call) => ({
      id: call.toolCallId,
      name: call.toolName,
      args: toToolCallArgs(call.input),
    })),
  });
}
