import { z } from "zod";

import { ANALYZER_NAMES } from "../config.js";
import { analysisErrorSchema, toolHistoryEntrySchema } from "../graph/state.js";
import { secFlowFindingSchema } from "../graph/schema/analyzer.js";
import { ruleArtifactSchema } from "../graph/schema/rules.js";

export const REPORT_ANALYZER_NAMES = [...ANALYZER_NAMES, "url", "classifier"] as const;

const reportAnalyzerSchema = z.enum(REPORT_ANALYZER_NAMES);

const reportRuleSchema = z
  .object({
    rule_name: z.string().min(1).max(200),
    description: z.string().max(2_000).optional(),
    reasoning: z.string().max(10_000).optional(),
    tags: z.array(z.string().max(100)).max(50).optional(),
    log_source: z.string().max(200).optional(),
    rule_text: z.string().min(1).max(200_000),
  })
  .loose();

const ruleSectionSchema = z
  .object({
    reasoning: z.string().max(10_000).optional(),
    total_rules: z.number().int().nonnegative(),
    rules: z.array(reportRuleSchema).max(50),
  })
  .loose();

export const threatIntelSchema = z
  .object({
    model: z.string().max(200).optional(),
    error: z.string().max(4_000).nullable().optional(),
    threat_summary: z.record(z.string(), z.unknown()).optional(),
    yara: ruleSectionSchema.optional(),
    sigma: ruleSectionSchema.optional(),
  })
  .loose();

export const pwndocReportSchema = z
  .object({
    input: z.string().min(1).max(1_024),
    total_passes: z.number().int().min(1),
    overall_risk_score: z.number().min(0).max(10),
    summary: z.string().min(1).max(8_000),
    passes: z
      .array(
        z
          .object({
            pass_number: z.number().int().min(1),
            analyzer: reportAnalyzerSchema,
            findings: z.array(secFlowFindingSchema).max(2_000),
          })
          .strict(),
      )
      .min(1)
      .max(100),
    recommendations: z.array(z.string().max(4_000)).max(50),
    threat_intel: threatIntelSchema.optional(),
    rules: z
      .object({
        yara: z.array(ruleArtifactSchema).max(50),
        sigma: z.array(ruleArtifactSchema).max(50),
        skipReason: z.string().max(2_000).optional(),
      })
      .optional(),
    tools: z.array(toolHistoryEntrySchema).max(500).optional(),
    errors: z.array(analysisErrorSchema).max(500).optional(),
    analyzers_executed: z.array(z.string().max(100)).max(20).optional(),
    limitations: z.array(z.string().max(1_000)).max(50).optional(),
    timestamps: z
      .object({
        started_at: z.string().datetime(),
        generated_at: z.string().datetime(),
      })
      .optional(),
  })
  .loose();
export type PwndocReport = z.infer<typeof pwndocReportSchema>;
