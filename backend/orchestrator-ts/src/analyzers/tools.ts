import type { AppConfig, AnalyzerName } from "../config.js";
import type { Logger } from "../logger.js";
import {
  analyzerToolOutputSchema,
  secFlowResultSchema,
  summarizeFindings,
  type SecFlowFinding,
} from "../graph/schema/analyzer.js";
import { targetRefSchema, type AnalysisToolName, type TargetRef } from "../graph/schema/tools.js";
import { defineTool, ToolRegistry, type ToolContext } from "../graph/tools.js";
import type { AnalysisTarget, TargetKind } from "../graph/state.js";
import { createNetworkGuard, type NetworkGuard } from "../security/networkGuard.js";
import { truncate } from "./parse.js";
import type { AdaptedAnalyzerResult } from "./types.js";
import type { AnalyzerToolResult } from "./schema.js";
import { MacroAnalyzerClient } from "./clients/macro.js";
import { MalwareAnalyzerClient } from "./clients/malware.js";
import { ReconAnalyzerClient } from "./clients/recon.js";
import { StegAnalyzerClient } from "./clients/steg.js";
import { WebAnalyzerClient } from "./clients/web.js";

const ALLOWED_TARGET_KINDS: Record<AnalysisToolName, readonly TargetKind[]> = {
  analyze_malware: ["file"],
  analyze_steg: ["file"],
  analyze_recon: ["ip", "domain", "email", "phone", "username", "unknown"],
  analyze_web: ["url"],
  analyze_macro: ["file"],
};

const TOOL_DESCRIPTIONS: Record<AnalysisToolName, string> = {
  analyze_malware:
    "Analyze a binary file target (executable, PE, ELF, DLL, or extracted payload) with VirusTotal and Ghidra decompilation/objdump. Use only for file targets classified as executables. Pass a targetId from the target catalog; never pass a path or a URL.",
  analyze_steg:
    "Analyze an image file target for hidden or embedded data using the steg-analyzer tool set. Use only for image file targets. Pass a targetId from the target catalog; never pass a path.",
  analyze_recon:
    "Run threat-intelligence reconnaissance (/scan) for an IP or domain, or OSINT footprint (/footprint) for an email, phone number, username, or an unknown string that may be a username. Use when the target is one of those indicators or when findings expose one. Pass a targetId from the target catalog; never pass a raw value.",
  analyze_web:
    "Analyze an HTTP or HTTPS URL: reachability, security headers, TLS/SSL, HSTS, WAF, redirects, DNS, and malware/phishing checks. Use only for URL targets. Pass a targetId from the target catalog; never pass a URL directly.",
  analyze_macro:
    "Analyze an Office document or RTF file for VBA macros, XLM macros, obfuscated indicators, extracted IOCs, and VirusTotal verdicts. Use only for file targets classified as documents. Pass a targetId from the target catalog; never pass a path.",
};

export interface AnalyzerToolDependencies {
  name: AnalysisToolName;
  analyzer: AnalyzerName;
  run(target: AnalysisTarget, context: ToolContext): Promise<AdaptedAnalyzerResult>;
  /** SSRF policy applied before the analyzer receives a network target. */
  guard?: NetworkGuard;
}

function conciseFindings(findings: readonly SecFlowFinding[]): SecFlowFinding[] {
  return findings.slice(0, 50).map((finding) => ({
    type: finding.type,
    detail: truncate(finding.detail, 500),
    severity: finding.severity,
    ...(finding.evidence ? { evidence: truncate(finding.evidence, 500) } : {}),
    ...(finding.extracted_path !== undefined ? { extracted_path: finding.extracted_path } : {}),
  }));
}

export function createAnalyzerTool(deps: AnalyzerToolDependencies) {
  return defineTool<TargetRef, AnalyzerToolResult>({
    name: deps.name,
    description: TOOL_DESCRIPTIONS[deps.name],
    inputSchema: targetRefSchema,
    toModelOutput: (output) => output.modelOutput,
    async execute(input, context) {
      const target = context.targets?.get(input.targetId);
      if (!target) {
        const available = context.targets ? [...context.targets.keys()].join(", ") : "(none)";
        throw new Error(
          `Unknown targetId "${input.targetId}". Available target ids: ${available}.`,
        );
      }
      if (context.pass === undefined || context.pass < 1) {
        throw new Error("Analyzer tools require a valid pass number");
      }
      if (!context.rawOutputStore) {
        throw new Error("Analyzer tools require a raw output store");
      }

      const allowedKinds = ALLOWED_TARGET_KINDS[deps.name];
      if (!allowedKinds.includes(target.kind)) {
        throw new Error(
          `${deps.name} cannot analyze target kind "${target.kind}" (${target.id}); expected ${allowedKinds.join(" or ")}.`,
        );
      }

      await deps.guard?.assertTargetAllowed(target);

      const adapted = await deps.run(target, context);
      // Downloaded payloads always carry provenance evidence, even if the
      // analyzer finds nothing; this mirrors the Python pipeline.
      const findings: SecFlowFinding[] = target.sourceUrl
        ? [
            {
              type: "payload_downloaded",
              detail:
                `File downloaded from: ${target.sourceUrl}. ` +
                "Treat as inherently suspicious regardless of analysis results.",
              severity: "high",
              evidence: target.sourceUrl,
            },
            ...adapted.findings,
          ]
        : adapted.findings;
      const secFlow = secFlowResultSchema.parse({
        analyzer: deps.analyzer,
        pass: context.pass,
        input: target.displayName,
        findings,
        risk_score: adapted.riskScore,
        raw_output: adapted.rawOutput,
        ...(adapted.extractedFiles ? { extracted_files: adapted.extractedFiles } : {}),
      });

      const rawOutputRef = await context.rawOutputStore.put({
        analyzer: deps.analyzer,
        pass: context.pass,
        content: adapted.rawOutput,
      });

      const summary = truncate(
        [
          `${deps.analyzer} analysis of ${target.displayName}: ${findings.length} finding(s), risk ${adapted.riskScore.toFixed(1)}.`,
          summarizeFindings(findings, 8),
          "Full output is referenced by rawOutputRef; it is not included in this message.",
        ].join("\n"),
        4_000,
      );

      const modelOutput = analyzerToolOutputSchema.parse({
        analyzer: deps.analyzer,
        pass: context.pass,
        targetId: target.id,
        findings: conciseFindings(findings),
        riskScore: adapted.riskScore,
        findingCount: findings.length,
        summary,
        rawOutputRef,
        extractedFiles: adapted.extractedFiles ?? [],
      });

      return { modelOutput, secFlow };
    },
  });
}

/**
 * Build the five analyzer tools with real HTTP clients. Client instances are
 * shared per run; tool execution supplies the target catalog, pass number and
 * raw-output store through `ToolContext`.
 */
export function createAnalyzerToolRegistry(
  config: AppConfig,
  logger: Logger,
  options: { guard?: NetworkGuard } = {},
): ToolRegistry {
  const guard =
    options.guard ?? createNetworkGuard({ allowPrivateTargets: config.allowPrivateTargets });
  const maxResponseBytes = config.analyzerMaxResponseBytes;

  const malware = new MalwareAnalyzerClient({
    baseUrl: config.analyzers.malware.baseUrl,
    fileAnalysisTimeoutMs: config.analyzers.malware.timeoutOverrideMs ?? 60_000,
    decompileTimeoutMs: config.analyzers.malware.timeoutOverrideMs ?? 180_000,
    maxRetries: 0,
    maxResponseBytes,
    logger,
  });

  const steg = new StegAnalyzerClient({
    baseUrl: config.analyzers.steg.baseUrl,
    uploadTimeoutMs: config.analyzers.steg.timeoutOverrideMs ?? 30_000,
    statusTimeoutMs: config.analyzers.steg.timeoutOverrideMs ?? 10_000,
    resultTimeoutMs: config.analyzers.steg.timeoutOverrideMs ?? 30_000,
    maxRetries: 0,
    maxResponseBytes,
    logger,
  });

  const recon = new ReconAnalyzerClient({
    baseUrl: config.analyzers.recon.baseUrl,
    timeoutMs: config.analyzers.recon.timeoutMs,
    maxRetries: config.analyzerMaxRetries,
    maxResponseBytes,
    logger,
  });

  const web = new WebAnalyzerClient({
    baseUrl: config.analyzers.web.baseUrl,
    ...(config.analyzers.web.timeoutOverrideMs !== undefined
      ? { timeoutOverrideMs: config.analyzers.web.timeoutOverrideMs }
      : {}),
    maxRetries: config.analyzerMaxRetries,
    maxResponseBytes,
    logger,
  });

  const macro = new MacroAnalyzerClient({
    baseUrl: config.analyzers.macro.baseUrl,
    timeoutMs: config.analyzers.macro.timeoutMs,
    maxRetries: 0,
    maxResponseBytes,
    logger,
  });

  return new ToolRegistry([
    createAnalyzerTool({
      name: "analyze_malware",
      analyzer: "malware",
      guard,
      run: (target, context) => malware.analyze(target.value, context.signal),
    }),
    createAnalyzerTool({
      name: "analyze_steg",
      analyzer: "steg",
      guard,
      run: (target, context) => steg.analyze(target.value, context.signal),
    }),
    createAnalyzerTool({
      name: "analyze_recon",
      analyzer: "recon",
      guard,
      run: (target, context) => recon.analyze(target.value, target.displayName, context.signal),
    }),
    createAnalyzerTool({
      name: "analyze_web",
      analyzer: "web",
      guard,
      run: (target, context) => web.analyze(target.value, target.displayName, context.signal),
    }),
    createAnalyzerTool({
      name: "analyze_macro",
      analyzer: "macro",
      guard,
      run: (target, context) => macro.analyze(target.value, target.displayName, context.signal),
    }),
  ]);
}
