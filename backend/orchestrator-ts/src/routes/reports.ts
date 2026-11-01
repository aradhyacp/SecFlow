import { stat } from "node:fs/promises";
import path from "node:path";

import { Router } from "express";

import type { AppConfig } from "../config.js";
import { HttpError } from "../http/errors.js";

const REPORT_MIME = {
  json: "application/json",
  html: "text/html",
} as const;

type ReportFormat = keyof typeof REPORT_MIME;

const JOB_ID_RE = /^[0-9a-f]+$/;

function isReportFormat(value: string): value is ReportFormat {
  return value === "json" || value === "html";
}

export function createReportsRouter(config: AppConfig): Router {
  const router = Router();

  router.get("/report/:jobId/:fmt", async (req, res) => {
    const jobId = req.params.jobId ?? "";
    const fmt = req.params.fmt ?? "";

    if (!isReportFormat(fmt)) {
      throw new HttpError(400, `Unknown format '${fmt}'. Use json or html.`);
    }
    if (!JOB_ID_RE.test(jobId)) {
      throw new HttpError(400, "Invalid job_id");
    }

    const reportPath = path.join(config.reportsDir, jobId, `report.${fmt}`);

    // Defence in depth: the hex-only job id already prevents traversal.
    if (path.dirname(path.dirname(reportPath)) !== config.reportsDir) {
      throw new HttpError(400, "Invalid job_id");
    }

    try {
      await stat(reportPath);
    } catch {
      throw new HttpError(404, `Report not found for job_id '${jobId}'`);
    }

    res.type(REPORT_MIME[fmt]);
    if (fmt === "json") {
      res.download(reportPath, `secflow_report_${jobId}.json`, (error) => {
        if (error && !res.headersSent) {
          res.status(500).json({ error: "Failed to send report" });
        }
      });
      return;
    }

    res.sendFile(reportPath);
  });

  return router;
}
