import type { Logger } from "../logger.js";
import type { ToolContext, ToolExecutionResult, ToolRegistry } from "./tools.js";
import { makeErrorId, makeToolRecordId } from "./ids.js";
import {
  analysisStateSchema,
  type AnalysisError,
  type AnalysisState,
  type ToolStatus,
} from "./state.js";
import { ruleGenerationOutputSchema, type RuleGenerationOutput } from "./schema/rules.js";
import { reportToolOutputSchema, type ReportToolOutput } from "./schema/tools.js";

export interface FinalizeAnalysisOptions {
  state: AnalysisState | Readonly<AnalysisState>;
  registry: ToolRegistry;
  /** Stable report id; normally sha256(input)[:16] from the runner. */
  jobId?: string;
  logger?: Logger;
  signal?: AbortSignal;
  now?: () => Date;
}

function truncate(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function riskOf(state: AnalysisState): number {
  return Math.round(Math.max(0, ...state.findings.map((result) => result.risk_score)) * 100) / 100;
}

function contextFor(state: AnalysisState, options: FinalizeAnalysisOptions): ToolContext {
  return {
    runId: state.runId,
    ...(options.jobId ? { jobId: options.jobId } : {}),
    ...(options.logger ? { logger: options.logger } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    state,
    pass: state.counters.passes,
    targets: new Map(state.targets.map((target) => [target.id, target])),
  };
}

function addError(
  state: AnalysisState,
  stage: AnalysisError["stage"],
  code: string,
  message: string,
  at: string,
): void {
  if (state.errors.length >= 500) {
    return;
  }
  state.errors.push({
    id: makeErrorId(stage, `${code}:${message}`, state.errors.length),
    stage,
    code: truncate(code, 100),
    message: truncate(message, 4_000),
    recoverable: true,
    at,
  });
}

function addHistory(
  state: AnalysisState,
  input: {
    tool: string;
    targetId?: string;
    status: ToolStatus;
    startedAt: string;
    durationMs: number;
    findingCount: number;
    riskScore: number;
    summary: string;
    error?: string;
  },
): void {
  if (state.toolHistory.length >= 500) {
    return;
  }
  state.toolHistory.push({
    id: makeToolRecordId(input.tool, input.targetId ?? "none", state.toolHistory.length),
    pass: state.counters.passes,
    tool: input.tool as AnalysisState["toolHistory"][number]["tool"],
    ...(input.targetId ? { targetId: input.targetId } : {}),
    status: input.status,
    startedAt: input.startedAt,
    durationMs: input.durationMs,
    findingCount: input.findingCount,
    riskScore: input.riskScore,
    summary: truncate(input.summary, 4_000),
    ...(input.error ? { error: truncate(input.error, 4_000) } : {}),
  });
}

function executionFailureMessage(result: ToolExecutionResult): string {
  return result.ok ? "" : result.error;
}

async function runRuleTool(
  name: "generate_yara" | "generate_sigma",
  state: AnalysisState,
  options: FinalizeAnalysisOptions,
  now: Date,
): Promise<RuleGenerationOutput | null> {
  const tool = options.registry.get(name);
  if (!tool) {
    const message = `${name} is not registered`;
    addError(state, "runtime", `${name}_unavailable`, message, now.toISOString());
    return null;
  }

  const startedMs = Date.now();
  const result = await options.registry.execute(name, {}, contextFor(state, options));
  const durationMs = Date.now() - startedMs;
  if (!result.ok) {
    const message = executionFailureMessage(result);
    addError(state, "tool", `${name}_failed`, message, now.toISOString());
    addHistory(state, {
      tool: name,
      status: "failed",
      startedAt: new Date(startedMs).toISOString(),
      durationMs,
      findingCount: 0,
      riskScore: 0,
      summary: `${name} failed.`,
      error: message,
    });
    return null;
  }

  const parsed = ruleGenerationOutputSchema.safeParse(result.output);
  if (!parsed.success) {
    const message = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    addError(state, "validation", `${name}_output_invalid`, message, now.toISOString());
    addHistory(state, {
      tool: name,
      status: "failed",
      startedAt: new Date(startedMs).toISOString(),
      durationMs,
      findingCount: 0,
      riskScore: 0,
      summary: `${name} returned an invalid output contract.`,
      error: message,
    });
    return null;
  }

  const output = parsed.data;
  if (output.kind !== name.replace("generate_", "")) {
    const message = `${name} returned kind ${output.kind}`;
    addError(state, "validation", `${name}_kind_mismatch`, message, now.toISOString());
    addHistory(state, {
      tool: name,
      status: "failed",
      startedAt: new Date(startedMs).toISOString(),
      durationMs,
      findingCount: 0,
      riskScore: 0,
      summary: `${name} returned the wrong rule kind.`,
      error: message,
    });
    return null;
  }
  if (output.error) {
    addError(state, "validation", `${name}_validation`, output.error, now.toISOString());
  }

  addHistory(state, {
    tool: name,
    status:
      output.status === "generated"
        ? "succeeded"
        : output.status === "skipped"
          ? "skipped"
          : "failed",
    startedAt: new Date(startedMs).toISOString(),
    durationMs,
    findingCount: output.rules.length,
    riskScore: 0,
    summary: output.reason ?? `${name}: ${output.rules.length} rule(s), status ${output.status}.`,
    ...(output.error ? { error: output.error } : {}),
  });
  return output;
}

async function runReportTool(
  state: AnalysisState,
  options: FinalizeAnalysisOptions,
  now: Date,
): Promise<ReportToolOutput | null> {
  const tool = options.registry.get("generate_report");
  if (!tool) {
    const message = "generate_report is not registered";
    addError(state, "runtime", "generate_report_unavailable", message, now.toISOString());
    state.report = {
      status: "failed",
      totalPasses: state.findings.length,
      overallRiskScore: riskOf(state),
      summary: "Report generation is not configured.",
      recommendations: [],
      error: message,
    };
    return null;
  }

  const startedMs = Date.now();
  const result = await options.registry.execute("generate_report", {}, contextFor(state, options));
  const durationMs = Date.now() - startedMs;
  if (!result.ok) {
    const message = executionFailureMessage(result);
    addError(state, "report", "generate_report_failed", message, now.toISOString());
    addHistory(state, {
      tool: "generate_report",
      status: "failed",
      startedAt: new Date(startedMs).toISOString(),
      durationMs,
      findingCount: 0,
      riskScore: riskOf(state),
      summary: "Report generation failed.",
      error: message,
    });
    state.report = {
      status: "failed",
      totalPasses: state.findings.length,
      overallRiskScore: riskOf(state),
      summary: "Report generation failed.",
      recommendations: [],
      error: message,
      generatedAt: now.toISOString(),
    };
    return null;
  }

  const parsed = reportToolOutputSchema.safeParse(result.output);
  if (!parsed.success) {
    const message = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    addError(state, "report", "generate_report_output_invalid", message, now.toISOString());
    state.report = {
      status: "failed",
      totalPasses: state.findings.length,
      overallRiskScore: riskOf(state),
      summary: "Report generation returned an invalid output contract.",
      recommendations: [],
      error: message,
      generatedAt: now.toISOString(),
    };
    return null;
  }

  const output = parsed.data;
  if (output.status === "failed") {
    addError(
      state,
      "report",
      "generate_report_failed",
      output.reason ?? "Report failed.",
      now.toISOString(),
    );
  }
  state.report = {
    status: output.status,
    totalPasses: state.findings.length,
    overallRiskScore: output.overallRiskScore,
    summary: output.summary,
    recommendations: output.recommendations,
    ...(output.jsonPath ? { jsonPath: output.jsonPath } : {}),
    ...(output.htmlPath ? { htmlPath: output.htmlPath } : {}),
    ...(output.status === "generated" ? { generatedAt: now.toISOString() } : {}),
    ...(output.reason ? { error: output.reason } : {}),
  };
  addHistory(state, {
    tool: "generate_report",
    status:
      output.status === "generated"
        ? "succeeded"
        : output.status === "skipped"
          ? "skipped"
          : "failed",
    startedAt: new Date(startedMs).toISOString(),
    durationMs,
    findingCount: state.findings.length,
    riskScore: output.overallRiskScore,
    summary: output.summary,
    ...(output.reason ? { error: output.reason } : {}),
  });
  return output;
}

/**
 * Post-analysis stage: generate rules, then build the report from the validated
 * state. Each stage is independent and a failure is recorded rather than
 * crashing the run. The analysis termination reason is preserved.
 */
export async function finalizeAnalysis(options: FinalizeAnalysisOptions): Promise<AnalysisState> {
  const state = analysisStateSchema.parse(options.state);
  if (state.report.status === "generated") {
    return state;
  }

  const now = options.now?.() ?? new Date();
  const yara = await runRuleTool("generate_yara", state, options, now);
  const sigma = await runRuleTool("generate_sigma", state, options, now);

  const skipReasons: string[] = [];
  if (yara?.status === "skipped" && yara.reason) {
    skipReasons.push(`YARA: ${yara.reason}`);
  }
  if (sigma?.status === "skipped" && sigma.reason) {
    skipReasons.push(`SIGMA: ${sigma.reason}`);
  }
  state.rules = {
    yara: yara?.rules ?? [],
    sigma: sigma?.rules ?? [],
    ...(skipReasons.length > 0 ? { skipReason: truncate(skipReasons.join(" "), 2_000) } : {}),
  };

  await runReportTool(state, options, now);
  return analysisStateSchema.parse(state);
}
