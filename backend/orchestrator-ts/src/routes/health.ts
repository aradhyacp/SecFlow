import { mkdir, access } from "node:fs/promises";
import { constants } from "node:fs";

import { Router } from "express";

import type { AppConfig } from "../config.js";

export interface HealthDependencies {
  config: AppConfig;
  startedAt: number;
}

async function reportsDirWritable(config: AppConfig): Promise<boolean> {
  try {
    await mkdir(config.reportsDir, { recursive: true });
    await access(config.reportsDir, constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

export function createHealthRouter({ config, startedAt }: HealthDependencies): Router {
  const router = Router();

  // Kept byte-compatible with the Python orchestrator health payload.
  router.get("/health", (_req, res) => {
    res.status(200).json({ status: "healthy", service: "secflow-orchestrator" });
  });

  router.get("/ready", async (_req, res) => {
    const checks = {
      model: config.model.apiKey !== null,
      reports: await reportsDirWritable(config),
    };
    const ready = checks.model && checks.reports;

    res.status(ready ? 200 : 503).json({
      status: ready ? "ready" : "not_ready",
      service: "secflow-orchestrator",
      checks,
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      model: config.model.modelId,
    });
  });

  return router;
}
