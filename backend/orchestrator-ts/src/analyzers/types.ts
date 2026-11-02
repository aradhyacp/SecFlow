import type { SecFlowFinding } from "../graph/schema/analyzer.js";

export interface AdaptedAnalyzerResult {
  findings: SecFlowFinding[];
  riskScore: number;
  rawOutput: string;
  extractedFiles?: string[];
}
