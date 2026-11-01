import { mkdirSync } from "node:fs";

import { createApp } from "./app.js";
import { ConfigError, loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { createAnalysisRunner } from "./pipeline/index.js";

function loadDotEnv(): void {
  // Optional: docker-compose injects env vars directly.
  try {
    process.loadEnvFile();
  } catch {
    // no .env file — expected in containers
  }
}

function main(): void {
  loadDotEnv();

  let config;
  try {
    config = loadConfig();
  } catch (error) {
    const message = error instanceof ConfigError ? error.message : String(error);
    console.error(`[secflow-orchestrator] ${message}`);
    process.exitCode = 1;
    return;
  }

  const logger = createLogger(config);
  mkdirSync(config.reportsDir, { recursive: true });

  if (!config.model.apiKey) {
    logger.warn(
      "OPENROUTER_API_KEY is not set — /api/ready will report not_ready and analysis requests will fail",
    );
  }

  const runner = createAnalysisRunner(config, logger);
  const app = createApp({ config, runner, logger });

  const server = app.listen(config.port, config.host, () => {
    logger.info(
      {
        port: config.port,
        host: config.host,
        model: config.model.modelId,
        reportsDir: config.reportsDir,
        node: process.version,
      },
      "secflow orchestrator listening",
    );
  });

  const shutdown = (signal: string): void => {
    logger.info({ signal }, "shutting down");
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main();
