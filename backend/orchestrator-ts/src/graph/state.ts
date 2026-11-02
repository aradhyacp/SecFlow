import { Annotation } from "@langchain/langgraph";
import { z } from "zod";

import { secFlowResultSchema, type SecFlowResult } from "./schema/analyzer.js";
import { rulesStateSchema, type RulesState } from "./schema/rules.js";
import { analysisToolNameSchema, toolNameSchema, TARGET_ID_PATTERN } from "./schema/tools.js";
import { internalAnalyzerNameSchema } from "./schema/analyzer.js";

export const INPUT_KINDS = ["file", "target"] as const;
export const inputKindSchema = z.enum(INPUT_KINDS);

export const INPUT_TYPES = [
  "image",
  "document",
  "executable",
  "url",
  "ip",
  "domain",
  "email",
  "phone",
  "username",
  "unknown",
] as const;
export const inputTypeSchema = z.enum(INPUT_TYPES);
export type InputType = z.infer<typeof inputTypeSchema>;

export const TARGET_KINDS = [
  "file",
  "url",
  "ip",
  "domain",
  "email",
  "phone",
  "username",
  "unknown",
] as const;
export const targetKindSchema = z.enum(TARGET_KINDS);
export type TargetKind = z.infer<typeof targetKindSchema>;

export const TARGET_ORIGINS = ["user_input", "classifier", "artifact", "payload_download"] as const;
export const targetOriginSchema = z.enum(TARGET_ORIGINS);

export const inputSourceSchema = z
  .object({
    kind: inputKindSchema,
    /** Safe for prompts/reports; never a temp path. */
    displayName: z.string().min(1).max(1_024),
    originalName: z.string().min(1).max(1_024).optional(),
    mimeType: z.string().min(1).max(255).optional(),
    sizeBytes: z.number().int().nonnegative().optional(),
  })
  .strict();
export type InputSource = z.infer<typeof inputSourceSchema>;

export const analysisTargetSchema = z
  .object({
    id: z.string().regex(/^tgt_[a-f0-9]{16}$/),
    kind: targetKindSchema,
    /**
     * Backend-resolved file path or canonical indicator. Never sent to the
     * model; the model only sees `id` and `displayName`.
     */
    value: z.string().min(1).max(4_096),
    displayName: z.string().min(1).max(1_024),
    origin: targetOriginSchema,
    mimeType: z.string().min(1).max(255).optional(),
    sizeBytes: z.number().int().nonnegative().optional(),
    /** Source URL for payload_download targets; never sent to the model. */
    sourceUrl: z.string().min(1).max(4_096).optional(),
  })
  .strict();
export type AnalysisTarget = z.infer<typeof analysisTargetSchema>;

export const classificationSchema = z
  .object({
    inputType: inputTypeSchema,
    analyzer: z.enum(["malware", "steg", "recon", "web", "macro"]).nullable(),
    mimeType: z.string().max(255),
    magicOutput: z.string().max(10_000),
    /** Printable prefix of an unknown/ambiguous file for model fallback. */
    fileHead: z.string().max(4_096).optional(),
    deterministic: z.boolean(),
    reasoning: z.string().max(2_000).optional(),
  })
  .strict();
export type Classification = z.infer<typeof classificationSchema>;

/**
 * A model (or deterministic classifier) choice for the next analysis action.
 * `tool` is an enumerated analyzer tool and `targetId` must resolve through the
 * trusted target catalog; no path, URL or command is accepted here.
 */
export const analysisActionSchema = z
  .object({
    tool: analysisToolNameSchema,
    targetId: z.string().regex(TARGET_ID_PATTERN),
    reasoning: z.string().min(1).max(2_000),
  })
  .strict();
export type AnalysisAction = z.infer<typeof analysisActionSchema>;

export const analysisContextSchema = z
  .object({
    runId: z.string().min(1).max(200),
    startedAt: z.string().datetime(),
    maxPasses: z.union([z.literal(3), z.literal(4), z.literal(5)]),
    maxCycles: z.number().int().positive().max(20),
    maxToolCalls: z.number().int().positive().max(50),
    modelId: z.string().min(1).max(200),
  })
  .strict();
export type AnalysisContext = z.infer<typeof analysisContextSchema>;

export const TOOL_STATUSES = ["succeeded", "failed", "rejected", "skipped"] as const;
export const toolStatusSchema = z.enum(TOOL_STATUSES);
export type ToolStatus = z.infer<typeof toolStatusSchema>;

export const toolHistoryEntrySchema = z
  .object({
    id: z.string().regex(/^tool_[a-f0-9]{16}$/),
    pass: z.number().int().min(0).max(100),
    tool: toolNameSchema,
    targetId: z
      .string()
      .regex(/^tgt_[a-f0-9]{16}$/)
      .optional(),
    status: toolStatusSchema,
    startedAt: z.string().datetime(),
    durationMs: z.number().int().nonnegative(),
    findingCount: z.number().int().nonnegative(),
    riskScore: z.number().min(0).max(10),
    rawOutputRef: z
      .string()
      .regex(/^raw_[a-f0-9]{16}$/)
      .optional(),
    summary: z.string().max(4_000),
    reasoning: z.string().max(2_000).optional(),
    error: z.string().max(4_000).optional(),
  })
  .strict();
export type ToolHistoryEntry = z.infer<typeof toolHistoryEntrySchema>;

export const ERROR_STAGES = [
  "classification",
  "model",
  "tool",
  "validation",
  "report",
  "runtime",
] as const;
export const errorStageSchema = z.enum(ERROR_STAGES);

export const analysisErrorSchema = z
  .object({
    id: z.string().regex(/^err_[a-f0-9]{16}$/),
    stage: errorStageSchema,
    code: z.string().min(1).max(100),
    message: z.string().min(1).max(4_000),
    recoverable: z.boolean(),
    at: z.string().datetime(),
  })
  .strict();
export type AnalysisError = z.infer<typeof analysisErrorSchema>;

export const TERMINATION_REASONS = [
  "max_passes",
  "model_finished",
  "no_artifacts",
  "duplicate_analysis",
  "max_cycles",
  "max_tool_calls",
  "timeout",
  "fatal_error",
  "unsupported_input",
] as const;
export const terminationReasonSchema = z.enum(TERMINATION_REASONS);
export type TerminationReason = z.infer<typeof terminationReasonSchema>;

export const terminationSchema = z
  .object({
    reason: terminationReasonSchema,
    pass: z.number().int().min(0).max(100),
    detail: z.string().min(1).max(4_000),
    at: z.string().datetime(),
  })
  .strict();
export type Termination = z.infer<typeof terminationSchema>;

export const REPORT_STATUSES = ["not_started", "generated", "failed", "skipped"] as const;
export const reportStatusSchema = z.enum(REPORT_STATUSES);

export const reportStateSchema = z
  .object({
    status: reportStatusSchema,
    totalPasses: z.number().int().min(0).max(100),
    overallRiskScore: z.number().min(0).max(10),
    summary: z.string().max(8_000),
    recommendations: z.array(z.string().max(4_000)).max(50),
    jsonPath: z.string().max(4_096).optional(),
    htmlPath: z.string().max(4_096).optional(),
    generatedAt: z.string().datetime().optional(),
    error: z.string().max(4_000).optional(),
  })
  .strict();
export type ReportState = z.infer<typeof reportStateSchema>;

export const countersSchema = z
  .object({
    passes: z.number().int().nonnegative(),
    cycles: z.number().int().nonnegative(),
    toolCalls: z.number().int().nonnegative(),
    duplicateRejections: z.number().int().nonnegative(),
  })
  .strict();
export type RunCounters = z.infer<typeof countersSchema>;

export const INDICATOR_KINDS = [
  "url",
  "ip",
  "domain",
  "email",
  "phone",
  "username",
  "hash",
] as const;
export const indicatorKindSchema = z.enum(INDICATOR_KINDS);
export type IndicatorKind = z.infer<typeof indicatorKindSchema>;

export const indicatorSchema = z
  .object({
    id: z.string().regex(/^ioc_[a-f0-9]{16}$/),
    kind: indicatorKindSchema,
    /** Untrusted evidence; validate and normalize before using it as a target. */
    value: z.string().min(1).max(2_048),
    sourceAnalyzer: internalAnalyzerNameSchema,
    sourcePass: z.number().int().min(1).max(100),
    confidence: z.number().min(0).max(1).optional(),
  })
  .strict();
export type Indicator = z.infer<typeof indicatorSchema>;

/**
 * Aggregate validator for a complete graph state snapshot. LangGraph channels
 * do not validate on every update, so initial state, persistence boundaries and
 * tests use this schema explicitly.
 */
export const analysisStateSchema = z
  .object({
    runId: z.string().min(1).max(200),
    source: inputSourceSchema,
    target: analysisTargetSchema,
    targets: z.array(analysisTargetSchema).max(500),
    indicators: z.array(indicatorSchema).max(1_000),
    classification: classificationSchema,
    inputType: inputTypeSchema,
    context: analysisContextSchema,
    findings: z.array(secFlowResultSchema).max(500),
    toolHistory: z.array(toolHistoryEntrySchema).max(500),
    errors: z.array(analysisErrorSchema).max(500),
    rules: rulesStateSchema,
    report: reportStateSchema,
    termination: terminationSchema.nullable(),
    pendingAction: analysisActionSchema.nullable().default(null),
    counters: countersSchema,
  })
  .strict();
export type AnalysisState = z.infer<typeof analysisStateSchema>;

function append<T>(left: T[], right: T | T[]): T[] {
  return left.concat(Array.isArray(right) ? right : [right]);
}

function replace<T>(_current: T, next: T): T {
  return next;
}

function mergeTargets(
  left: AnalysisTarget[],
  right: AnalysisTarget | AnalysisTarget[],
): AnalysisTarget[] {
  const merged = new Map(left.map((target) => [target.id, target]));
  for (const target of Array.isArray(right) ? right : [right]) {
    merged.set(target.id, target);
  }
  return [...merged.values()];
}

export function emptyReportState(): ReportState {
  return {
    status: "not_started",
    totalPasses: 0,
    overallRiskScore: 0,
    summary: "",
    recommendations: [],
  };
}

export function emptyCounters(): RunCounters {
  return { passes: 0, cycles: 0, toolCalls: 0, duplicateRejections: 0 };
}

/**
 * Typed state carried by the orchestrator graph. Arrays are append-only so
 * every tool/pass contributes without a node having to read-modify-write.
 */
export const AnalysisStateAnnotation = Annotation.Root({
  runId: Annotation<string>({ reducer: replace, default: () => "" }),
  source: Annotation<InputSource>(),
  target: Annotation<AnalysisTarget>(),
  targets: Annotation<AnalysisTarget[]>({
    reducer: mergeTargets,
    default: () => [],
  }),
  indicators: Annotation<Indicator[]>({
    reducer: append,
    default: () => [],
  }),
  classification: Annotation<Classification>(),
  inputType: Annotation<InputType>({ reducer: replace, default: () => "unknown" }),
  context: Annotation<AnalysisContext>(),
  findings: Annotation<SecFlowResult[]>({
    reducer: append,
    default: () => [],
  }),
  toolHistory: Annotation<ToolHistoryEntry[]>({
    reducer: append,
    default: () => [],
  }),
  errors: Annotation<AnalysisError[]>({
    reducer: append,
    default: () => [],
  }),
  rules: Annotation<RulesState>({ reducer: replace, default: () => ({ yara: [], sigma: [] }) }),
  report: Annotation<ReportState>({ reducer: replace, default: emptyReportState }),
  termination: Annotation<Termination | null>({ reducer: replace, default: () => null }),
  pendingAction: Annotation<AnalysisAction | null>({ reducer: replace, default: () => null }),
  counters: Annotation<RunCounters>({ reducer: replace, default: emptyCounters }),
});

export type AnalysisGraphState = typeof AnalysisStateAnnotation.State;

/** Validate a complete snapshot without narrowing the graph's inferred type. */
export function validateAnalysisState(state: unknown): AnalysisState {
  return analysisStateSchema.parse(state);
}
