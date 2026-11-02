import { randomUUID } from "node:crypto";

import { Router } from "express";
import type { Multer } from "multer";

import type { AppConfig } from "../config.js";
import { HttpError } from "../http/errors.js";
import { resolveInput } from "../pipeline/resolveInput.js";
import type { AnalysisRunner, PassCount } from "../pipeline/types.js";
import { SsrfBlockedError } from "../security/networkGuard.js";

export interface AnalyzeDependencies {
  config: AppConfig;
  runner: AnalysisRunner;
  upload: Multer;
}

const ALLOWED_PASSES: readonly PassCount[] = [3, 4, 5];
const INTEGER_RE = /^[+-]?\d+$/;

/**
 * Mirror the Python parser: non-numeric input silently falls back to 3,
 * numeric values outside {3,4,5} are a 400.
 */
export function parsePasses(raw: unknown): PassCount {
  const value: unknown = Array.isArray(raw) ? (raw as unknown[])[0] : raw;
  if (typeof value !== "string" || !INTEGER_RE.test(value.trim())) {
    return 3;
  }
  const parsed = Number(value);
  if (!ALLOWED_PASSES.includes(parsed as PassCount)) {
    throw new HttpError(400, "passes must be 3, 4, or 5");
  }
  return parsed as PassCount;
}

export function createAnalyzeRouter({ config, runner, upload }: AnalyzeDependencies): Router {
  const router = Router();

  router.post("/smart-analyze", upload.single("file"), async (req, res) => {
    const passes = parsePasses(req.query.passes);
    const input = await resolveInput(req, config);
    const headerId = req.headers["x-request-id"];
    const runId =
      typeof headerId === "string" && headerId.trim().length > 0 && headerId.length <= 200
        ? headerId
        : randomUUID();

    try {
      const result = await runner.run({
        input,
        maxPasses: passes,
        runId,
        signal: AbortSignal.timeout(config.totalAnalysisTimeoutMs),
        logger: req.log,
      });

      res.status(200).json({
        job_id: result.jobId,
        passes_completed: result.passesCompleted,
        overall_risk_score: result.overallRiskScore,
        findings_summary: result.findingsSummary,
        report_paths: result.reportPaths,
        report_urls: result.reportUrls,
      });
    } catch (error) {
      if (error instanceof SsrfBlockedError) {
        throw new HttpError(400, error.message);
      }
      if (error instanceof Error && error.name === "TimeoutError") {
        throw new HttpError(504, "Analysis exceeded TOTAL_ANALYSIS_TIMEOUT_MS");
      }
      throw error;
    } finally {
      await input.cleanup();
    }
  });

  return router;
}
