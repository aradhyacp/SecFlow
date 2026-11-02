import { createAnalyzerTool } from "../../src/analyzers/tools.js";
import type { AdaptedAnalyzerResult } from "../../src/analyzers/types.js";
import type { AnalyzerName } from "../../src/config.js";
import type { AnalysisTarget } from "../../src/graph/state.js";
import { ToolRegistry } from "../../src/graph/tools.js";
import { analysisToolNames, type AnalysisToolName } from "../../src/graph/schema/tools.js";

const ANALYZER_BY_TOOL: Record<AnalysisToolName, AnalyzerName> = {
  analyze_malware: "malware",
  analyze_steg: "steg",
  analyze_recon: "recon",
  analyze_web: "web",
  analyze_macro: "macro",
};

export interface FakeToolCall {
  tool: AnalysisToolName;
  targetId: string;
  pass: number;
  target: AnalysisTarget;
}

export type FakeAnalyzerHandler = (
  tool: AnalysisToolName,
  target: AnalysisTarget,
  pass: number,
) => AdaptedAnalyzerResult | Promise<AdaptedAnalyzerResult>;

/** Build the real analyzer tools with deterministic in-process handlers. */
export function createFakeAnalyzerRegistry(handler: FakeAnalyzerHandler): {
  registry: ToolRegistry;
  calls: FakeToolCall[];
} {
  const calls: FakeToolCall[] = [];
  const tools = analysisToolNames.map((name) =>
    createAnalyzerTool({
      name,
      analyzer: ANALYZER_BY_TOOL[name],
      async run(target, context) {
        const pass = context.pass ?? 0;
        calls.push({ tool: name, targetId: target.id, pass, target });
        return handler(name, target, pass);
      },
    }),
  );
  return { registry: new ToolRegistry(tools), calls };
}

export function findingSet(detail = "synthetic finding"): AdaptedAnalyzerResult {
  return {
    findings: [{ type: "synthetic", detail, severity: "info" }],
    riskScore: 1,
    rawOutput: detail,
  };
}
