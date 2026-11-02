import type { InternalAnalyzerName, SecFlowResult, Severity } from "../graph/schema/analyzer.js";
import type { RuleKind } from "../graph/schema/rules.js";
import type { AnalysisState, AnalysisTarget, Indicator } from "../graph/state.js";
import { formatUntrusted, wrapUntrusted } from "../graph/untrusted.js";

export const MAX_RULE_EVIDENCE_ITEMS = 20;
export const MAX_RULE_EVIDENCE_CHARS = 24_000;
const MAX_EVIDENCE_PER_FINDING = 4_000;
const MAX_DETAIL_CHARS = 1_000;

export interface RuleEvidenceItem {
  ref: string;
  analyzer: InternalAnalyzerName;
  pass: number;
  type: string;
  severity: Severity;
  detail: string;
  evidence: string;
}

export interface RuleEvidence {
  kind: RuleKind;
  sufficient: boolean;
  reason: string;
  target: AnalysisTarget;
  sourceName: string;
  items: RuleEvidenceItem[];
  indicators: Indicator[];
  evidenceRefs: string[];
  /** Already wrapped/labelled untrusted text for the prompt. */
  formatted: string;
}

const FILE_ANALYZERS = new Set<InternalAnalyzerName>(["malware", "steg", "macro"]);
const NETWORK_ANALYZERS = new Set<InternalAnalyzerName>(["web", "recon"]);
const YARA_CONTENT_TYPES = new Set([
  "decompilation",
  "disassembly",
  "macro_source",
  "macro_xlm",
  "steg_hidden_data",
  "av_detection",
  "malware_detection",
  "embedded_payload",
]);

const NETWORK_IOC_RE =
  /https?:\/\/[^\s"'<>]+|\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b|\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}\b/;

function truncate(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function evidenceRef(result: SecFlowResult, index: number): string {
  return `${result.analyzer}:pass${result.pass}:finding${index + 1}`;
}

function isContentEvidence(
  result: SecFlowResult,
  finding: SecFlowResult["findings"][number],
): boolean {
  if (FILE_ANALYZERS.has(result.analyzer) && (finding.evidence?.trim().length ?? 0) >= 16) {
    return true;
  }
  return YARA_CONTENT_TYPES.has(finding.type);
}

function isSigmaRelevant(
  result: SecFlowResult,
  finding: SecFlowResult["findings"][number],
): boolean {
  const text = `${finding.type} ${finding.detail} ${finding.evidence ?? ""}`;
  if (NETWORK_ANALYZERS.has(result.analyzer) && finding.severity !== "info") {
    return true;
  }
  if (finding.severity === "critical" || finding.severity === "high") {
    return true;
  }
  return NETWORK_IOC_RE.test(text);
}

function toItem(result: SecFlowResult, index: number): RuleEvidenceItem {
  const finding = result.findings[index];
  if (!finding) {
    throw new Error("Evidence index out of range");
  }
  return {
    ref: evidenceRef(result, index),
    analyzer: result.analyzer,
    pass: result.pass,
    type: finding.type,
    severity: finding.severity,
    detail: truncate(finding.detail, MAX_DETAIL_CHARS),
    evidence: truncate(finding.evidence ?? "", MAX_EVIDENCE_PER_FINDING),
  };
}

function networkIndicators(state: AnalysisState): Indicator[] {
  return state.indicators.filter(
    (indicator) =>
      indicator.kind === "url" || indicator.kind === "ip" || indicator.kind === "domain",
  );
}

function formatEvidence(
  state: AnalysisState,
  kind: RuleKind,
  items: RuleEvidenceItem[],
  indicators: Indicator[],
): string {
  const lines = [
    `Rule kind: ${kind.toUpperCase()}`,
    `Input: ${state.source.displayName}`,
    `Target: ${state.target.displayName} (${state.target.kind})`,
    `Input type: ${state.inputType}`,
    `Analyzers executed: ${[...new Set(state.findings.map((result) => result.analyzer))].join(", ") || "none"}`,
    "",
    "Concrete network indicators:",
    ...(indicators.length > 0
      ? indicators.map(
          (indicator) =>
            `- ${indicator.kind}: ${indicator.value} (source ${indicator.sourceAnalyzer} pass ${indicator.sourcePass})`,
        )
      : ["- none"]),
    "",
    "Findings evidence:",
    ...(items.length > 0
      ? items.flatMap((item) => [
          `- [${item.ref}] [${item.severity}] ${item.type}`,
          `  detail: ${item.detail}`,
          ...(item.evidence ? [`  evidence: ${item.evidence}`] : []),
        ])
      : ["- none"]),
  ];

  const wrapped = wrapUntrusted("analyzer_output", lines.join("\n"), MAX_RULE_EVIDENCE_CHARS);
  return formatUntrusted(wrapped);
}

/**
 * Build a bounded, structured evidence packet for YARA or SIGMA generation.
 * Only normalized findings/indicators from validated graph state are used;
 * raw analyzer output and conversational text are deliberately excluded.
 */
export function buildRuleEvidence(state: AnalysisState, kind: RuleKind): RuleEvidence {
  const allItems: RuleEvidenceItem[] = [];
  for (const result of state.findings) {
    result.findings.forEach((finding, index) => {
      const include =
        kind === "yara"
          ? FILE_ANALYZERS.has(result.analyzer) || YARA_CONTENT_TYPES.has(finding.type)
          : isSigmaRelevant(result, finding);
      if (include) {
        allItems.push(toItem(result, index));
      }
    });
  }

  const items = allItems.slice(0, MAX_RULE_EVIDENCE_ITEMS);
  const indicators = networkIndicators(state);

  let sufficient: boolean;
  let reason: string;
  if (kind === "yara") {
    const hasContent = state.findings.some((result) =>
      result.findings.some(
        (finding) => FILE_ANALYZERS.has(result.analyzer) && isContentEvidence(result, finding),
      ),
    );
    sufficient = hasContent && items.length > 0;
    reason = sufficient
      ? "File/content evidence is sufficient for YARA rule generation."
      : "No file/content evidence is available for YARA rule generation.";
  } else {
    const relevantMediumOrHigher = items.some(
      (item) =>
        item.severity === "critical" || item.severity === "high" || item.severity === "medium",
    );
    sufficient = items.length > 0 && (indicators.length > 0 || relevantMediumOrHigher);
    reason = sufficient
      ? "Network/log evidence is sufficient for SIGMA rule generation."
      : "No relevant network or detection-log evidence is available for SIGMA rule generation.";
  }

  return {
    kind,
    sufficient,
    reason,
    target: state.target,
    sourceName: state.source.displayName,
    items,
    indicators,
    evidenceRefs: items.map((item) => item.ref),
    formatted: formatEvidence(state, kind, items, indicators),
  };
}
