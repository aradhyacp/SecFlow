import { createOpenRouter } from "@openrouter/ai-sdk-provider";
import type { LanguageModel } from "ai";

import { ConfigError, type AppConfig } from "../config.js";
import type { Logger } from "../logger.js";
import { OpenRouterModelClient } from "./client.js";

export interface BuiltModel {
  modelId: string;
  model: LanguageModel;
}

export interface ModelFactory {
  /** Injectable for tests; production uses the OpenRouter provider. */
  createModel(config: AppConfig): BuiltModel;
}

export const openRouterModelFactory: ModelFactory = {
  createModel(config) {
    const apiKey = config.model.apiKey;
    if (!apiKey) {
      throw new ConfigError(
        "OPENROUTER_API_KEY is not configured — analysis cannot run until it is set",
      );
    }

    const provider = createOpenRouter({
      apiKey,
      compatibility: "strict",
      appName: "SecFlow",
    });

    return {
      modelId: config.model.modelId,
      model: provider.chat(config.model.modelId),
    };
  },
};

/**
 * Central model construction. Nothing else in the service reads
 * OPENROUTER_API_KEY or names a model id.
 */
export function createModelClient(
  config: AppConfig,
  logger: Logger,
  factory: ModelFactory = openRouterModelFactory,
): OpenRouterModelClient {
  const { model, modelId } = factory.createModel(config);

  return new OpenRouterModelClient({
    model,
    modelId,
    temperature: config.model.temperature,
    maxTokens: config.model.maxTokens,
    timeoutMs: config.model.timeoutMs,
    maxRetries: config.model.maxRetries,
    logger,
  });
}

export type { LanguageModel };
