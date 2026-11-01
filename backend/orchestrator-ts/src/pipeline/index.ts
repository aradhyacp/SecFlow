import type { AppConfig } from "../config.js";
import { NotImplementedError } from "../http/errors.js";
import type { Logger } from "../logger.js";
import type { AnalysisRunner } from "./types.js";

/**
 * Build the production analysis runner.
 *
 * Steps 3–8 of the migration replace this shell with the OpenRouter model
 * provider, LangGraph workflow, analyzer tools, YARA/SIGMA tools and reporter.
 */
export function createAnalysisRunner(_config: AppConfig, _logger: Logger): AnalysisRunner {
  return {
    async run(): Promise<never> {
      throw new NotImplementedError(
        "Analysis pipeline is not implemented yet (migration step 2 service shell)",
      );
    },
  };
}
