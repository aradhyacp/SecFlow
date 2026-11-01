import express, { type Express } from "express";
import { pinoHttp } from "pino-http";
import { randomUUID } from "node:crypto";

import type { AppConfig } from "./config.js";
import { corsMiddleware, createErrorHandler } from "./http/middleware.js";
import type { Logger } from "./logger.js";
import type { AnalysisRunner } from "./pipeline/types.js";
import { createAnalyzeRouter } from "./routes/analyze.js";
import { createHealthRouter } from "./routes/health.js";
import { createReportsRouter } from "./routes/reports.js";
import { createUploadMiddleware } from "./pipeline/resolveInput.js";

export interface AppDependencies {
  config: AppConfig;
  runner: AnalysisRunner;
  logger: Logger;
  /** Overridable for deterministic tests. */
  startedAt?: number;
}

export function createApp({ config, runner, logger, startedAt }: AppDependencies): Express {
  const app = express();
  app.disable("x-powered-by");

  app.use(
    pinoHttp({
      logger,
      genReqId: (req, res) => {
        const existing = req.headers["x-request-id"];
        const id = typeof existing === "string" && existing.length > 0 ? existing : randomUUID();
        res.setHeader("x-request-id", id);
        return id;
      },
      autoLogging: config.env !== "test",
    }),
  );
  app.use(corsMiddleware);
  app.use(express.json({ limit: "1mb" }));

  const upload = createUploadMiddleware(config);

  app.use(
    "/api",
    createHealthRouter({ config, startedAt: startedAt ?? Date.now() }),
    createAnalyzeRouter({ config, runner, upload }),
    createReportsRouter(config),
  );

  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });
  app.use(createErrorHandler(logger));

  return app;
}
