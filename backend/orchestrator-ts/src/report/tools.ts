import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import type { Logger } from "../logger.js";
import type { ModelClient } from "../model/types.js";
import { defineTool, type RegisteredTool } from "../graph/tools.js";
import {
  generateReportInputSchema,
  reportToolOutputSchema,
  type GenerateReportInput,
  type ReportToolOutput,
} from "../graph/schema/tools.js";
import type { AnalysisState } from "../graph/state.js";
import { buildReport } from "./build.js";
import { renderReportHtml } from "./html.js";
import { enhanceReportNarrative } from "./narrative.js";
import { pwndocReportSchema, type PwndocReport } from "./schema.js";

export interface ReportToolOptions {
  reportsDir: string;
  /** Optional model for the executive narrative; the report is valid without it. */
  model?: ModelClient;
  logger?: Logger;
  now?: () => Date;
}

function safeJobId(jobId: string | undefined, runId: string): string {
  if (jobId && /^[a-f0-9]{16}$/.test(jobId)) {
    return jobId;
  }
  return createHash("sha256").update(runId).digest("hex").slice(0, 16);
}

function riskOf(state: AnalysisState): number {
  return Math.round(Math.max(...state.findings.map((result) => result.risk_score), 0) * 100) / 100;
}

function failureOutput(
  state: AnalysisState,
  reason: string,
  recommendations: string[] = [],
): ReportToolOutput {
  return {
    status: "failed",
    overallRiskScore: riskOf(state),
    summary: state.report.summary || "Report generation failed.",
    recommendations,
    reason,
  };
}

export function createReportTool(options: ReportToolOptions): RegisteredTool {
  return defineTool<GenerateReportInput, ReportToolOutput>({
    name: "generate_report",
    description:
      "Build the final PWNDoc-compatible JSON and HTML report from validated graph state. Takes no arguments.",
    inputSchema: generateReportInputSchema,
    toModelOutput(output) {
      return {
        status: output.status,
        overallRiskScore: output.overallRiskScore,
        jsonPath: output.jsonPath,
        htmlPath: output.htmlPath,
        reason: output.reason,
      };
    },
    async execute(_input, context) {
      const state = context.state;
      if (!state) {
        throw new Error("generate_report requires validated graph state");
      }
      if (state.findings.length === 0) {
        return {
          status: "skipped",
          overallRiskScore: 0,
          summary: "No analyzer findings were produced, so no report was generated.",
          recommendations: [],
          reason: "No analyzer findings were produced.",
        };
      }

      const now = options.now?.() ?? new Date();
      let report: PwndocReport;
      try {
        report = buildReport(state, now.toISOString());
        if (options.model) {
          const narrative = await enhanceReportNarrative(state, report, options.model, {
            ...(options.logger ? { logger: options.logger } : {}),
            ...(context.signal ? { signal: context.signal } : {}),
          });
          report = {
            ...report,
            summary: narrative.summary,
            recommendations: narrative.recommendations,
          };
        }
        const validated = pwndocReportSchema.safeParse(report);
        if (!validated.success) {
          const issues = validated.error.issues
            .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
            .join("; ");
          return failureOutput(state, `Report failed contract validation: ${issues}`);
        }
      } catch (error) {
        return failureOutput(
          state,
          `Report build failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      const jobId = safeJobId(context.jobId, context.runId);
      const directory = path.resolve(options.reportsDir, jobId);
      const jsonPath = path.join(directory, "report.json");
      const htmlPath = path.join(directory, "report.html");
      try {
        await mkdir(directory, { recursive: true });
        await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
        await writeFile(htmlPath, renderReportHtml(report, jobId), "utf8");
      } catch (error) {
        const reason = `Report write failed: ${error instanceof Error ? error.message : String(error)}`;
        options.logger?.error({ error: reason, jobId }, "report write failed");
        return failureOutput(state, reason, report.recommendations);
      }

      return {
        status: "generated",
        overallRiskScore: report.overall_risk_score,
        summary: report.summary,
        recommendations: report.recommendations,
        jsonPath,
        htmlPath,
      };
    },
  });
}

export { reportToolOutputSchema };
