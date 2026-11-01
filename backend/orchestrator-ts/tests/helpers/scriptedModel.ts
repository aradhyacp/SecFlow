import type { LanguageModel } from "ai";

import type {
  ModelClient,
  ModelDecision,
  ModelDecisionRequest,
  ModelUsage,
  StructuredObjectRequest,
} from "../../src/model/types.js";

export const TEST_USAGE: ModelUsage = {
  inputTokens: 10,
  outputTokens: 5,
  totalTokens: 15,
};

export function toolCallDecision(
  toolName: string,
  input: unknown,
  toolCallId = "call_1",
): ModelDecision {
  return {
    toolCalls: [{ toolCallId, toolName, input }],
    text: "",
    finishReason: "tool-calls",
    usage: TEST_USAGE,
  };
}

export function finishDecision(text: string): ModelDecision {
  return {
    toolCalls: [],
    text,
    finishReason: "stop",
    usage: TEST_USAGE,
  };
}

/**
 * Deterministic stand-in for the OpenRouter client. It records every request
 * so tests can assert what the graph sent back to the model.
 */
export class ScriptedModelClient implements ModelClient {
  readonly modelId = "scripted-test-model";
  readonly model = {} as LanguageModel;
  readonly requests: ModelDecisionRequest[] = [];
  private readonly decisions: ModelDecision[];

  constructor(decisions: ModelDecision[]) {
    this.decisions = [...decisions];
  }

  async decide(request: ModelDecisionRequest): Promise<ModelDecision> {
    this.requests.push(request);
    const decision = this.decisions.shift();
    if (!decision) {
      throw new Error("Scripted model ran out of decisions");
    }
    return decision;
  }

  async generateObject<T>(_request: StructuredObjectRequest<T>): Promise<T> {
    throw new Error("Scripted model does not implement generateObject");
  }
}
