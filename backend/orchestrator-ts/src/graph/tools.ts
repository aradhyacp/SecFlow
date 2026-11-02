import { tool as aiTool, type ToolSet } from "ai";
import type { z } from "zod";

import type { Logger } from "../logger.js";
import type { RawOutputStore } from "./rawOutputStore.js";
import type { AnalysisTarget } from "./state.js";

export interface ToolContext {
  runId: string;
  signal?: AbortSignal;
  logger?: Logger;
  /** 1-indexed pass currently executing. */
  pass?: number;
  /** Trusted target catalog for this run, keyed by target id. */
  targets?: ReadonlyMap<string, AnalysisTarget>;
  /** Full-output storage used by analyzer tools. */
  rawOutputStore?: RawOutputStore;
}

export type ToolFailureKind = "validation" | "execution" | "unknown_tool";

export type ToolExecutionResult =
  | { ok: true; output: unknown }
  | { ok: false; kind: ToolFailureKind; error: string };

export interface ToolSpec<TInput, TOutput = unknown> {
  name: string;
  description: string;
  inputSchema: z.ZodType<TInput>;
  execute(input: TInput, context: ToolContext): Promise<TOutput>;
  /** Projection sent back to the model; defaults to the raw tool output. */
  toModelOutput?(output: TOutput): unknown;
}

export interface RegisteredTool {
  name: string;
  description: string;
  inputSchema: z.ZodType;
  execute(rawInput: unknown, context: ToolContext): Promise<ToolExecutionResult>;
  toModelOutput(output: unknown): unknown;
}

export function formatIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => {
      const path = issue.path.length > 0 ? issue.path.join(".") : "(root)";
      return `${path}: ${issue.message}`;
    })
    .join("; ");
}

/**
 * Wrap a tool with argument validation. Validation and execution failures are
 * turned into values, never thrown: graph nodes must be able to feed a tool
 * error back to the model without aborting the run.
 */
export function defineTool<TInput, TOutput = unknown>(spec: ToolSpec<TInput, TOutput>): RegisteredTool {
  return {
    name: spec.name,
    description: spec.description,
    inputSchema: spec.inputSchema,
    toModelOutput(output) {
      return spec.toModelOutput ? spec.toModelOutput(output as TOutput) : output;
    },
    async execute(rawInput, context) {
      const parsed = spec.inputSchema.safeParse(rawInput);
      if (!parsed.success) {
        return {
          ok: false,
          kind: "validation",
          error: `Invalid arguments for ${spec.name}: ${formatIssues(parsed.error)}`,
        };
      }

      try {
        return { ok: true, output: await spec.execute(parsed.data, context) };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return { ok: false, kind: "execution", error: `${spec.name} failed: ${message}` };
      }
    },
  };
}

/**
 * The allowlist of tools exposed to the model. Only registered names can be
 * executed, and every call is schema-validated before it runs.
 */
export class ToolRegistry {
  private readonly tools = new Map<string, RegisteredTool>();

  constructor(tools: RegisteredTool[] = []) {
    for (const tool of tools) {
      if (this.tools.has(tool.name)) {
        throw new Error(`Duplicate tool name: ${tool.name}`);
      }
      this.tools.set(tool.name, tool);
    }
  }

  names(): string[] {
    return [...this.tools.keys()];
  }

  get(name: string): RegisteredTool | undefined {
    return this.tools.get(name);
  }

  /** AI SDK tool declarations without `execute`, so the SDK returns calls instead of running them. */
  toAiSdkTools(): ToolSet {
    const tools: ToolSet = {};
    for (const tool of this.tools.values()) {
      tools[tool.name] = aiTool({
        description: tool.description,
        inputSchema: tool.inputSchema,
      });
    }
    return tools;
  }

  async execute(
    name: string,
    rawInput: unknown,
    context: ToolContext,
  ): Promise<ToolExecutionResult> {
    const tool = this.tools.get(name);
    if (!tool) {
      return {
        ok: false,
        kind: "unknown_tool",
        error: `Unknown tool "${name}". Available tools: ${this.names().join(", ") || "(none)"}.`,
      };
    }
    return tool.execute(rawInput, context);
  }

  /** The provider-facing projection of a tool result. */
  toModelOutput(name: string, output: unknown): unknown {
    return this.tools.get(name)?.toModelOutput(output) ?? output;
  }
}
