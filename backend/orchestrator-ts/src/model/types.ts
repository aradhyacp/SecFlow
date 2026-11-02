import type { LanguageModel, ModelMessage, ToolSet } from "ai";
import type { z } from "zod";

export interface ToolCallRecord {
  toolCallId: string;
  toolName: string;
  input: unknown;
}

export interface ModelUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface ModelDecision {
  toolCalls: ToolCallRecord[];
  text: string;
  finishReason: string;
  usage: ModelUsage;
}

export interface ModelDecisionRequest {
  system?: string;
  messages: ModelMessage[];
  tools?: ToolSet;
  temperature?: number;
  maxOutputTokens?: number;
  /** Correlation id for structured logs; never sent to the provider as content. */
  runId?: string;
  abortSignal?: AbortSignal;
}

export interface StructuredObjectRequest<T> {
  system?: string;
  prompt: string;
  schema: z.ZodType<T>;
  temperature?: number;
  maxOutputTokens?: number;
  /** Correlation id for structured logs; never sent to the provider as content. */
  runId?: string;
  abortSignal?: AbortSignal;
}

/**
 * The only surface the graph knows about the model. Keeping the Vercel AI SDK
 * adapter behind this interface is the provider-compatibility gate from the
 * migration spec: swapping to @langchain/openrouter later would not touch the
 * graph.
 */
export interface ModelClient {
  readonly modelId: string;
  readonly model: LanguageModel;
  decide(request: ModelDecisionRequest): Promise<ModelDecision>;
  generateObject<T>(request: StructuredObjectRequest<T>): Promise<T>;
}
