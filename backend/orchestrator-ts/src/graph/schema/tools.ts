import { z } from "zod";

import { ruleGenerationOutputSchema } from "./rules.js";
import { analyzerToolOutputSchema, riskScoreSchema } from "./analyzer.js";

export const TARGET_ID_PATTERN = /^tgt_[a-z0-9]{8,32}$/;

/**
 * Tools never accept paths, URLs, shell commands, or service addresses from the
 * model. They accept a target id that the backend resolves against the trusted
 * target catalog in graph state.
 */
export const targetRefSchema = z
  .object({
    targetId: z.string().regex(TARGET_ID_PATTERN, "targetId must reference a known analysis target"),
  })
  .strict();
export type TargetRef = z.infer<typeof targetRefSchema>;

export const analysisToolNames = [
  "analyze_malware",
  "analyze_steg",
  "analyze_recon",
  "analyze_web",
  "analyze_macro",
] as const;

export const generationToolNames = ["generate_yara", "generate_sigma", "generate_report"] as const;

export const toolNameSchema = z.enum([...analysisToolNames, ...generationToolNames]);
export type ToolName = z.infer<typeof toolNameSchema>;
export type AnalysisToolName = (typeof analysisToolNames)[number];
export type GenerationToolName = (typeof generationToolNames)[number];

export const analyzeMalwareInputSchema = targetRefSchema;
export const analyzeStegInputSchema = targetRefSchema;
export const analyzeReconInputSchema = targetRefSchema;
export const analyzeWebInputSchema = targetRefSchema;
export const analyzeMacroInputSchema = targetRefSchema;

/** Rule and report tools read validated evidence from state; they take no free-form arguments. */
export const generateYaraInputSchema = z.object({}).strict();
export const generateSigmaInputSchema = z.object({}).strict();
export const generateReportInputSchema = z.object({}).strict();

export type GenerateYaraInput = z.infer<typeof generateYaraInputSchema>;
export type GenerateSigmaInput = z.infer<typeof generateSigmaInputSchema>;
export type GenerateReportInput = z.infer<typeof generateReportInputSchema>;

export const reportToolOutputSchema = z
  .object({
    status: z.enum(["generated", "failed", "skipped"]),
    overallRiskScore: riskScoreSchema,
    summary: z.string().max(8_000),
    recommendations: z.array(z.string().max(4_000)).max(50),
    jsonPath: z.string().max(4096).optional(),
    htmlPath: z.string().max(4096).optional(),
    reason: z.string().max(4_000).optional(),
  })
  .strict();
export type ReportToolOutput = z.infer<typeof reportToolOutputSchema>;

export const ANALYSIS_TOOL_INPUT_SCHEMAS: Record<AnalysisToolName, typeof targetRefSchema> = {
  analyze_malware: analyzeMalwareInputSchema,
  analyze_steg: analyzeStegInputSchema,
  analyze_recon: analyzeReconInputSchema,
  analyze_web: analyzeWebInputSchema,
  analyze_macro: analyzeMacroInputSchema,
};

export const TOOL_OUTPUT_SCHEMAS = {
  analyzer: analyzerToolOutputSchema,
  rules: ruleGenerationOutputSchema,
  report: reportToolOutputSchema,
} as const;
