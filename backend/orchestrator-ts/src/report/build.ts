import type { PwndocReport } from "./schema.js";
import type { AnalysisState } from "../graph/state.js";
import type { RuleArtifact, RulesState } from "../graph/schema/rules.js";
import type { SecFlowFinding } from "../graph/schema/analyzer.js";

const SEVERITY_ORDER: Record<SecFlowFinding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Mirrors the Python reporter's risk thresholds. */
export function riskLabel(score: number): string {
  if (score >= 8) {
    return "critical";
  }
  if (score >= 6) {
    return "high";
  }
  if (score >= 4) {
    return "medium";
  }
  if (score >= 2) {
    return "low";
  }
  return "informational";
}

function truncate(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function flattenFindings(state: AnalysisState): SecFlowFinding[] {
  return state.findings.flatMap((result) => result.findings);
}

const ANALYZER_BY_TOOL: Record<string, string> = {
  analyze_malware: "malware",
  analyze_steg: "steg",
  analyze_recon: "recon",
  analyze_web: "web",
  analyze_macro: "macro",
};

function uniqueAnalyzers(state: AnalysisState): string[] {
  const analyzers: string[] = state.findings.map((result) => result.analyzer);
  for (const entry of state.toolHistory) {
    const analyzer = ANALYZER_BY_TOOL[entry.tool];
    if (analyzer && (entry.status === "succeeded" || entry.status === "failed")) {
      analyzers.push(analyzer);
    }
  }
  return [...new Set(analyzers)];
}

function buildSummary(state: AnalysisState, score: number): string {
  const findings = flattenFindings(state);
  const analyzers = uniqueAnalyzers(state);
  const top = [...findings]
    .sort((left, right) => SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity])
    .slice(0, 3)
    .map((finding) => `${finding.severity} ${finding.type}`)
    .join(", ");
  const parts = [
    `Automated analysis of "${state.source.displayName}" completed ${state.findings.length} pass(es) across ${
      analyzers.length > 0 ? analyzers.join(", ") : "no analyzers"
    }.`,
    `Overall risk is ${score.toFixed(1)}/10 (${riskLabel(score)}) based on ${findings.length} finding(s).`,
  ];
  if (top) {
    parts.push(`Highest-priority findings: ${top}.`);
  }
  return truncate(parts.join(" "), 8_000);
}

const RECOMMENDATION_RULES: ReadonlyArray<{ pattern: RegExp; advice: string }> = [
  {
    pattern: /av_detection|malware_detection|malicious|trojan|ransom|backdoor|dropper/i,
    advice:
      "Isolate affected hosts, block the identified file hashes and network indicators, and submit the sample for sandbox confirmation.",
  },
  {
    pattern: /payload|downloaded|download/i,
    advice:
      "Treat the downloaded payload as untrusted, block its source URL, and inspect endpoint logs for execution.",
  },
  {
    pattern: /header|tls|certificate|cookie|hsts|csp|security_header/i,
    advice:
      "Remediate the identified web security misconfiguration and re-scan the endpoint after applying the fix.",
  },
  {
    pattern: /vulnerab|xss|sqli|injection|rce|traversal|ssrf|open_redirect/i,
    advice:
      "Prioritize remediation of the identified vulnerability, add a regression test, and re-run the web analysis.",
  },
  {
    pattern: /blocklist|blacklist|tor_exit|threatfox|malware|ioc|indicator|talos/i,
    advice:
      "Block the indicator at network controls and search historical logs for prior contact with the same infrastructure.",
  },
  {
    pattern: /breach|credential|password|exposed_email/i,
    advice:
      "Force a credential reset for affected accounts, enable MFA, and review identity-provider logs for suspicious sign-ins.",
  },
  {
    pattern: /steg|hidden_data|embedded|extracted|payload/i,
    advice:
      "Quarantine the source file, preserve the extracted payload, and inspect it in an isolated malware-analysis environment.",
  },
  {
    pattern: /macro|vba|xlm|document/i,
    advice:
      "Disable macros by policy, quarantine the document, and review email-gateway delivery records for other recipients.",
  },
  {
    pattern: /username|email|phone|osint|footprint/i,
    advice:
      "Review the exposed account footprint with the affected user and reduce publicly discoverable personal information.",
  },
];

function buildRecommendations(state: AnalysisState, score: number): string[] {
  const findings = [...flattenFindings(state)].sort(
    (left, right) => SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity],
  );
  const recommendations: string[] = [];
  const add = (value: string) => {
    if (recommendations.length < 50 && !recommendations.includes(value)) {
      recommendations.push(value);
    }
  };

  for (const finding of findings) {
    if (finding.severity !== "critical" && finding.severity !== "high") {
      continue;
    }
    const text = `${finding.type} ${finding.detail}`;
    for (const rule of RECOMMENDATION_RULES) {
      if (rule.pattern.test(text)) {
        add(rule.advice);
      }
    }
  }

  if (recommendations.length === 0 && score >= 2) {
    add(
      "Review the high-priority findings, validate them manually, and remediate before re-running the analysis.",
    );
  }
  if (recommendations.length === 0) {
    add(
      "No immediate action is required; continue monitoring and retain the report for audit purposes.",
    );
  }
  return recommendations;
}

function deployableRules(rules: readonly RuleArtifact[]): RuleArtifact[] {
  return rules.filter((rule) => rule.status === "valid" || rule.status === "generated");
}

function legacyRule(rule: RuleArtifact): {
  rule_name: string;
  description?: string;
  reasoning?: string;
  tags?: string[];
  rule_text: string;
} {
  return {
    rule_name: rule.name ?? `${rule.kind.toUpperCase()}_SecFlow_Rule`,
    ...(rule.description ? { description: rule.description } : {}),
    ...(rule.reasoning ? { reasoning: rule.reasoning } : {}),
    ...(rule.tags.length > 0 ? { tags: rule.tags } : {}),
    rule_text: rule.content,
  };
}

function legacyRuleSection(
  rules: readonly RuleArtifact[],
  skipReason: string | undefined,
): { reasoning?: string; total_rules: number; rules: ReturnType<typeof legacyRule>[] } | undefined {
  const deployable = deployableRules(rules);
  if (deployable.length === 0 && !skipReason) {
    return undefined;
  }
  const reasoning = deployable
    .map((rule) => rule.reasoning)
    .filter(Boolean)
    .join("\n\n")
    .slice(0, 10_000);
  return {
    ...(reasoning ? { reasoning } : skipReason ? { reasoning: skipReason } : {}),
    total_rules: deployable.length,
    rules: deployable.map(legacyRule),
  };
}

function buildLimitations(state: AnalysisState): string[] {
  const limitations: string[] = [];
  if (
    state.termination &&
    state.termination.reason !== "model_finished" &&
    state.termination.reason !== "no_artifacts"
  ) {
    limitations.push(
      `Analysis stopped with reason "${state.termination.reason}": ${state.termination.detail}`,
    );
  }
  if (state.errors.length > 0) {
    limitations.push(
      `${state.errors.length} recoverable error(s) occurred; see the errors section for details.`,
    );
  }
  if (state.rules.skipReason) {
    limitations.push(`Rule generation skipped: ${state.rules.skipReason}`);
  }
  const invalidRules = [...state.rules.yara, ...state.rules.sigma].filter(
    (rule) => rule.status === "invalid",
  );
  if (invalidRules.length > 0) {
    limitations.push(
      `${invalidRules.length} generated rule(s) failed validation and are excluded from the deployable rule set.`,
    );
  }
  if (state.indicators.length === 0) {
    limitations.push(
      "No network indicators were extracted, so network hunting coverage is limited.",
    );
  }
  limitations.push("Findings are automated analyzer results and have not been manually validated.");
  return limitations.slice(0, 50).map((item) => truncate(item, 1_000));
}

function buildRulesState(state: AnalysisState): PwndocReport["rules"] {
  return {
    yara: state.rules.yara,
    sigma: state.rules.sigma,
    ...(state.rules.skipReason ? { skipReason: state.rules.skipReason } : {}),
  };
}

/**
 * Build the deterministic, PWNDoc-compatible report from validated graph state.
 * No model call is made here, so the report cannot invent evidence or findings.
 */
export function buildReport(state: AnalysisState, generatedAt: string): PwndocReport {
  if (state.findings.length === 0) {
    throw new Error("Cannot build a report without analyzer findings");
  }

  const score =
    Math.round(Math.max(...state.findings.map((result) => result.risk_score), 0) * 100) / 100;
  const analyzers = uniqueAnalyzers(state);
  const rules: RulesState = state.rules;
  const yaraSection = legacyRuleSection(rules.yara, rules.skipReason);
  const sigmaSection = legacyRuleSection(rules.sigma, rules.skipReason);

  const report: PwndocReport = {
    input: state.source.displayName,
    total_passes: state.findings.length,
    overall_risk_score: score,
    summary: buildSummary(state, score),
    passes: state.findings.map((result, index) => ({
      pass_number: result.pass > 0 ? result.pass : index + 1,
      analyzer: result.analyzer,
      findings: result.findings,
    })),
    recommendations: buildRecommendations(state, score),
    ...(yaraSection || sigmaSection
      ? {
          threat_intel: {
            model: state.context.modelId,
            error: null,
            ...(yaraSection ? { yara: yaraSection } : {}),
            ...(sigmaSection ? { sigma: sigmaSection } : {}),
          },
        }
      : {}),
    rules: buildRulesState(state),
    tools: state.toolHistory,
    errors: state.errors,
    analyzers_executed: analyzers,
    limitations: buildLimitations(state),
    timestamps: {
      started_at: state.context.startedAt,
      generated_at: generatedAt,
    },
  };

  return report;
}
