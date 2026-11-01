import type { AnalyzerName } from "../config.js";

export type PassCount = 3 | 4 | 5;

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type InternalAnalyzerName = AnalyzerName | "url" | "classifier";

export interface SecFlowFinding {
  type: string;
  detail: string;
  severity: Severity;
  evidence?: string;
  extracted_path?: string | null;
}

/** The SecFlow analyzer output contract, unchanged since the Python orchestrator. */
export interface SecFlowResult {
  analyzer: InternalAnalyzerName;
  pass: number;
  input: string;
  findings: SecFlowFinding[];
  risk_score: number;
  raw_output: string;
  extracted_files?: string[];
}

export interface ResolvedInput {
  kind: "file" | "target";
  /** Temp file path for uploads, trimmed target string otherwise. */
  value: string;
  /** Human-readable identifier used in prompts/reports (never the raw temp path). */
  displayName: string;
  originalName?: string;
  mimeType?: string;
  sizeBytes?: number;
  cleanup(): Promise<void>;
}

export interface AnalysisRequest {
  input: ResolvedInput;
  maxPasses: PassCount;
  runId: string;
  signal: AbortSignal;
  logger: import("../logger.js").Logger;
}

export interface ReportPaths {
  json: string;
  html: string;
}

export interface ReportUrls {
  json: string;
  html: string;
}

export interface AnalysisResponse {
  jobId: string;
  passesCompleted: number;
  overallRiskScore: number;
  findingsSummary: SecFlowResult[];
  reportPaths: ReportPaths;
  reportUrls: ReportUrls;
}

export interface AnalysisRunner {
  run(request: AnalysisRequest): Promise<AnalysisResponse>;
}
