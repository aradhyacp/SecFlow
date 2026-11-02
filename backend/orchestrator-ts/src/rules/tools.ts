import type { Logger } from "../logger.js";
import type { ModelClient } from "../model/types.js";
import { defineTool, type RegisteredTool } from "../graph/tools.js";
import {
  generateSigmaInputSchema,
  generateYaraInputSchema,
  type GenerateSigmaInput,
  type GenerateYaraInput,
} from "../graph/schema/tools.js";
import type { RuleGenerationOutput } from "../graph/schema/rules.js";
import type { AnalysisState } from "../graph/state.js";
import { generateSigmaRules, generateYaraRules } from "./generate.js";

export interface RuleToolOptions {
  model: ModelClient;
  logger?: Logger;
  now?: () => Date;
}

function requireState(state: Readonly<AnalysisState> | undefined, tool: string): AnalysisState {
  if (!state) {
    throw new Error(`${tool} requires validated graph state`);
  }
  return state;
}

export function createYaraGenerationTool(options: RuleToolOptions): RegisteredTool {
  return defineTool<GenerateYaraInput, RuleGenerationOutput>({
    name: "generate_yara",
    description:
      "Generate and compile YARA rules from file/content evidence in validated graph state. Takes no arguments.",
    inputSchema: generateYaraInputSchema,
    toModelOutput(output) {
      return {
        kind: output.kind,
        status: output.status,
        ruleCount: output.rules.length,
        reason: output.reason,
        error: output.error,
      };
    },
    async execute(_input, context) {
      const state = requireState(context.state, "generate_yara");
      return generateYaraRules(state, {
        model: options.model,
        ...(options.logger ? { logger: options.logger } : {}),
        ...(options.now ? { now: options.now } : {}),
        ...(context.signal ? { signal: context.signal } : {}),
      });
    },
  });
}

export function createSigmaGenerationTool(options: RuleToolOptions): RegisteredTool {
  return defineTool<GenerateSigmaInput, RuleGenerationOutput>({
    name: "generate_sigma",
    description:
      "Generate and validate SIGMA rules from network/log evidence in validated graph state. Takes no arguments.",
    inputSchema: generateSigmaInputSchema,
    toModelOutput(output) {
      return {
        kind: output.kind,
        status: output.status,
        ruleCount: output.rules.length,
        reason: output.reason,
        error: output.error,
      };
    },
    async execute(_input, context) {
      const state = requireState(context.state, "generate_sigma");
      return generateSigmaRules(state, {
        model: options.model,
        ...(options.logger ? { logger: options.logger } : {}),
        ...(options.now ? { now: options.now } : {}),
        ...(context.signal ? { signal: context.signal } : {}),
      });
    },
  });
}

export function createRuleGenerationTools(options: RuleToolOptions): RegisteredTool[] {
  return [createYaraGenerationTool(options), createSigmaGenerationTool(options)];
}
