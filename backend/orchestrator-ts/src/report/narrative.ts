import type { Logger } from "../logger.js";
import type { ModelClient } from "../model/types.js";
import type { AnalysisState } from "../graph/state.js";
import type { PwndocReport } from "./schema.js";
import { formatUntrusted, wrapUntrusted } from "../graph/untrusted.js";
import {
  buildReportPrompt,
  REPORT_SYSTEM_PROMPT,
  reportNarrativeSchema,
  type ReportNarrative,
} from "../prompts/report.js";

export interface ReportNarrativeOptions {
  logger?: Logger;
  signal?: AbortSignal;
}

function truncate(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function compactEvidence(state: AnalysisState, report: PwndocReport): string {
  const passes = report.passes.map((pass) => {
    const findings = pass.findings
      .slice(0, 12)
      .map(
        (finding) => `  - [${finding.severity}] ${finding.type}: ${truncate(finding.detail, 400)}`,
      )
      .join("\n");
    return `- Pass ${pass.pass_number} (${pass.analyzer}): ${pass.findings.length} finding(s)\n${findings || "  - none"}`;
  });
  const indicators =
    state.indicators.length > 0
      ? state.indicators
          .slice(0, 50)
          .map(
            (indicator) =>
              `- ${indicator.kind}: ${JSON.stringify(indicator.value)} (${indicator.sourceAnalyzer} pass ${indicator.sourcePass})`,
          )
          .join("\n")
      : "- none";
  const rules = report.rules;
  const deployableYara = rules?.yara.filter(
    (rule) => rule.status === "valid" || rule.status === "generated",
  ).length;
  const deployableSigma = rules?.sigma.filter(
    (rule) => rule.status === "valid" || rule.status === "generated",
  ).length;
  const invalidRules = [...(rules?.yara ?? []), ...(rules?.sigma ?? [])].filter(
    (rule) => rule.status === "invalid",
  ).length;
  const errors =
    report.errors && report.errors.length > 0
      ? report.errors
          .slice(0, 20)
          .map((error) => `- ${error.stage}/${error.code}: ${truncate(error.message, 500)}`)
          .join("\n")
      : "- none";

  return [
    "## Report facts",
    `Input name: ${JSON.stringify(report.input)}`,
    `Overall risk: ${report.overall_risk_score}/10`,
    `Total passes: ${report.total_passes}`,
    `Analyzers executed: ${(report.analyzers_executed ?? []).join(", ") || "none"}`,
    `Termination: ${state.termination ? `${state.termination.reason}: ${state.termination.detail}` : "not recorded"}`,
    "",
    "## Passes and findings",
    ...(passes.length > 0 ? passes : ["- none"]),
    "",
    "## Network indicators",
    indicators,
    "",
    "## Generated rules",
    `- Deployable YARA: ${deployableYara ?? 0}`,
    `- Deployable SIGMA: ${deployableSigma ?? 0}`,
    `- Invalid rules excluded: ${invalidRules}`,
    ...(rules?.skipReason ? [`- Rule generation skip reason: ${rules.skipReason}`] : []),
    "",
    "## Errors",
    errors,
    "",
    "## Limitations",
    ...(report.limitations && report.limitations.length > 0
      ? report.limitations.map((limitation) => `- ${limitation}`)
      : ["- none recorded"]),
  ].join("\n");
}

export function evidenceForReport(state: AnalysisState, report: PwndocReport): string {
  return formatUntrusted(wrapUntrusted("analyzer_output", compactEvidence(state, report)));
}

function fallback(report: PwndocReport): ReportNarrative {
  return {
    summary: report.summary,
    recommendations:
      report.recommendations.length > 0
        ? report.recommendations
        : ["Review the findings and remediate the highest-severity issues first."],
  };
}

/**
 * Optional model-written narrative. The report structure/findings still come
 * from deterministic state; a model failure falls back to the baseline text.
 */
export async function enhanceReportNarrative(
  state: AnalysisState,
  report: PwndocReport,
  model: ModelClient,
  options: ReportNarrativeOptions = {},
): Promise<ReportNarrative> {
  try {
    const result = await model.generateObject({
      system: REPORT_SYSTEM_PROMPT,
      prompt: buildReportPrompt({ evidence: evidenceForReport(state, report) }),
      schema: reportNarrativeSchema,
      temperature: 0.1,
      // Leave room for reasoning tokens before the JSON narrative.
      maxOutputTokens: 2_048,
      runId: state.runId,
      ...(options.signal ? { abortSignal: options.signal } : {}),
    });
    return reportNarrativeSchema.parse(result);
  } catch (error) {
    options.logger?.warn(
      { error: error instanceof Error ? error.message : String(error) },
      "report narrative enhancement failed; using deterministic baseline",
    );
    return fallback(report);
  }
}
