import { generateText, Output, stepCountIs, type LanguageModel } from "ai";

import { ModelContractError } from "../http/errors.js";
import type { Logger } from "../logger.js";
import type {
  ModelClient,
  ModelDecision,
  ModelDecisionRequest,
  StructuredObjectRequest,
  ToolCallRecord,
} from "./types.js";

export interface OpenRouterModelClientOptions {
  model: LanguageModel;
  modelId: string;
  temperature: number;
  maxTokens: number;
  timeoutMs: number;
  maxRetries: number;
  logger: Logger;
}

function withTimeout(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function asNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function normalizeUsage(usage: {
  inputTokens?: number | undefined;
  outputTokens?: number | undefined;
  totalTokens?: number | undefined;
}): { inputTokens: number; outputTokens: number; totalTokens: number } {
  const inputTokens = asNumber(usage.inputTokens);
  const outputTokens = asNumber(usage.outputTokens);
  const total = asNumber(usage.totalTokens);
  return {
    inputTokens,
    outputTokens,
    totalTokens: total > 0 ? total : inputTokens + outputTokens,
  };
}

/**
 * Vercel AI SDK implementation of the model interface, pointed at OpenRouter.
 *
 * `decide()` intentionally runs a single step (`stepCountIs(1)`): tools are
 * declared without `execute`, so the SDK returns the tool calls for the graph
 * to run and feed back. This is the adapter the migration spec asks for.
 */
export class OpenRouterModelClient implements ModelClient {
  readonly modelId: string;
  readonly model: LanguageModel;
  private readonly options: OpenRouterModelClientOptions;

  constructor(options: OpenRouterModelClientOptions) {
    this.options = options;
    this.model = options.model;
    this.modelId = options.modelId;
  }

  async decide(request: ModelDecisionRequest): Promise<ModelDecision> {
    const startedAt = Date.now();
    const result = await generateText({
      model: this.model,
      ...(request.system ? { system: request.system } : {}),
      messages: request.messages,
      ...(request.tools ? { tools: request.tools } : {}),
      stopWhen: stepCountIs(1),
      temperature: request.temperature ?? this.options.temperature,
      maxOutputTokens: request.maxOutputTokens ?? this.options.maxTokens,
      maxRetries: this.options.maxRetries,
      abortSignal: withTimeout(request.abortSignal, this.options.timeoutMs),
    });

    const toolCalls = (result.toolCalls as ToolCallRecord[]).map((call) => ({
      toolCallId: call.toolCallId,
      toolName: call.toolName,
      input: call.input,
    }));

    const decision: ModelDecision = {
      toolCalls,
      text: result.text,
      finishReason: result.finishReason,
      usage: normalizeUsage(result.usage),
    };

    this.options.logger.debug(
      {
        model: this.modelId,
        toolCalls: decision.toolCalls.map((call) => call.toolName),
        finishReason: decision.finishReason,
        usage: decision.usage,
        durationMs: Date.now() - startedAt,
      },
      "model decision",
    );

    return decision;
  }

  async generateObject<T>(request: StructuredObjectRequest<T>): Promise<T> {
    const startedAt = Date.now();
    try {
      const result = await generateText({
        model: this.model,
        output: Output.object({ schema: request.schema }),
        ...(request.system ? { system: request.system } : {}),
        prompt: request.prompt,
        temperature: request.temperature ?? this.options.temperature,
        maxOutputTokens: request.maxOutputTokens ?? this.options.maxTokens,
        maxRetries: this.options.maxRetries,
        abortSignal: withTimeout(request.abortSignal, this.options.timeoutMs),
      });

      this.options.logger.debug(
        { model: this.modelId, durationMs: Date.now() - startedAt, usage: result.usage },
        "model structured object",
      );

      return result.output;
    } catch (error) {
      throw new ModelContractError(
        `Model ${this.modelId} did not return a valid structured object: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}
