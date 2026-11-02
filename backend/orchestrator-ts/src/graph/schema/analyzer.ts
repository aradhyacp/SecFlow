import { z } from "zod";

import { ANALYZER_NAMES } from "../../config.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const severitySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof severitySchema>;

/** Analyzers reachable over HTTP. `url` is legacy-only and is not exposed as a tool. */
export const internalAnalyzerNameSchema = z.enum([...ANALYZER_NAMES, "url"]);
export type InternalAnalyzerName = z.infer<typeof internalAnalyzerNameSchema>;

export const riskScoreSchema = z.number().min(0).max(10);

export const secFlowFindingSchema = z
  .object({
    type: z.string().min(1).max(200),
    detail: z.string().min(1).max(20_000),
    severity: severitySchema,
    evidence: z.string().max(2_000_000).optional(),
    extracted_path: z.string().max(4096).nullable().optional(),
  })
  .strict();
export type SecFlowFinding = z.infer<typeof secFlowFindingSchema>;

/**
 * The externally visible SecFlow analyzer contract, unchanged from the Python
 * orchestrator. `raw_output` is kept for API/report parity; tools return a
 * concise projection to the model instead.
 */
export const secFlowResultSchema = z
  .object({
    analyzer: internalAnalyzerNameSchema,
    pass: z.number().int().min(0).max(100),
    input: z.string().min(1).max(4096),
    findings: z.array(secFlowFindingSchema).max(2_000),
    risk_score: riskScoreSchema,
    raw_output: z.string().max(10_000_000),
    extracted_files: z.array(z.string().max(4096)).optional(),
  })
  .strict();
export type SecFlowResult = z.infer<typeof secFlowResultSchema>;

export const RAW_OUTPUT_PREVIEW_CHARS = 2_000;

export const rawOutputRefSchema = z
  .object({
    id: z.string().regex(/^raw_[a-f0-9]{16}$/),
    analyzer: internalAnalyzerNameSchema,
    pass: z.number().int().min(0).max(100),
    bytes: z.number().int().nonnegative(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
    preview: z.string().max(RAW_OUTPUT_PREVIEW_CHARS),
  })
  .strict();
export type RawOutputRef = z.infer<typeof rawOutputRefSchema>;

/** The concise analyzer result fed back to the model. */
export const analyzerToolOutputSchema = z
  .object({
    analyzer: internalAnalyzerNameSchema,
    pass: z.number().int().min(1).max(100),
    targetId: z.string().regex(/^tgt_[a-z0-9]{8,32}$/),
    findings: z.array(secFlowFindingSchema).max(200),
    riskScore: riskScoreSchema,
    findingCount: z.number().int().nonnegative(),
    summary: z.string().min(1).max(4_000),
    rawOutputRef: rawOutputRefSchema,
    extractedFiles: z.array(z.string().max(4096)).default([]),
    error: z.string().max(4_000).optional(),
  })
  .strict();
export type AnalyzerToolOutput = z.infer<typeof analyzerToolOutputSchema>;

export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 4.0,
  high: 2.5,
  medium: 1.0,
  low: 0.3,
  info: 0.0,
};

/** Shared risk roll-up for analyzers that use severity weights. */
export function severityRiskScore(findings: readonly SecFlowFinding[]): number {
  const total = findings.reduce((sum, finding) => sum + SEVERITY_WEIGHTS[finding.severity], 0);
  return Math.round(Math.min(10, total) * 100) / 100;
}

export function summarizeFindings(findings: readonly SecFlowFinding[], limit = 12): string {
  if (findings.length === 0) {
    return "No findings.";
  }
  const lines = findings.slice(0, limit).map(
    (finding) => `- [${finding.severity}] ${finding.type}: ${finding.detail}`,
  );
  if (findings.length > limit) {
    lines.push(`- … ${findings.length - limit} more finding(s) in the detailed result.`);
  }
  return lines.join("\n");
}
