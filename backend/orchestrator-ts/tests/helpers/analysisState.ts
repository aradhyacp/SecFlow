import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { makeIndicatorId, makeTargetId } from "../../src/graph/ids.js";
import type { SecFlowResult } from "../../src/graph/schema/analyzer.js";
import type {
  AnalysisState,
  AnalysisTarget,
  Indicator,
  Termination,
} from "../../src/graph/state.js";

const fixturePath = fileURLToPath(
  new URL("../../../../docs/ts-migration/fixtures/smart-analyze-response.json", import.meta.url),
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  findings_summary: SecFlowResult[];
};

export function fixtureFindings(): SecFlowResult[] {
  return structuredClone(fixture.findings_summary);
}

export function makeState(
  overrides: Partial<AnalysisState> = {},
  findings: SecFlowResult[] = fixtureFindings(),
): AnalysisState {
  const target: AnalysisTarget = {
    id: makeTargetId("file", "/tmp/invoice.docm"),
    kind: "file",
    value: "/tmp/invoice.docm",
    displayName: "invoice.docm",
    origin: "classifier",
    mimeType: "application/vnd.ms-word.document.macroenabled.12",
    sizeBytes: 12_345,
  };
  const indicators: Indicator[] = [
    {
      id: makeIndicatorId("domain", "recongraph.xyz"),
      kind: "domain",
      value: "recongraph.xyz",
      sourceAnalyzer: "macro",
      sourcePass: 1,
      confidence: 0.9,
    },
    {
      id: makeIndicatorId("url", "http://recongraph.xyz/payload.exe"),
      kind: "url",
      value: "http://recongraph.xyz/payload.exe",
      sourceAnalyzer: "macro",
      sourcePass: 1,
      confidence: 0.9,
    },
  ];
  const termination: Termination = {
    reason: "model_finished",
    pass: findings.length,
    detail: "The model finished analysis.",
    at: "2026-11-01T00:05:00.000Z",
  };
  const state: AnalysisState = {
    runId: "run-report-test",
    source: {
      kind: "file",
      displayName: "invoice.docm",
      originalName: "invoice.docm",
      mimeType: "application/vnd.ms-word.document.macroenabled.12",
      sizeBytes: 12_345,
    },
    target,
    targets: [target],
    indicators,
    classification: {
      inputType: "document",
      analyzer: "macro",
      mimeType: "application/vnd.ms-word.document.macroenabled.12",
      magicOutput: "Microsoft Word 2007+",
      deterministic: true,
    },
    inputType: "document",
    context: {
      runId: "run-report-test",
      startedAt: "2026-11-01T00:00:00.000Z",
      maxPasses: 3,
      maxCycles: 12,
      maxToolCalls: 20,
      modelId: "nvidia/nemotron-3-ultra-550b-a55b:free",
    },
    findings,
    toolHistory: findings.map((result, index) => ({
      id: `tool_${String(index + 1).padStart(16, "0")}`,
      pass: result.pass,
      tool:
        result.analyzer === "macro"
          ? "analyze_macro"
          : result.analyzer === "recon"
            ? "analyze_recon"
            : "analyze_web",
      targetId: target.id,
      status: "succeeded",
      startedAt: "2026-11-01T00:00:00.000Z",
      durationMs: 10,
      findingCount: result.findings.length,
      riskScore: result.risk_score,
      summary: `${result.analyzer} completed`,
    })),
    errors: [],
    rules: { yara: [], sigma: [] },
    report: {
      status: "not_started",
      totalPasses: 0,
      overallRiskScore: 0,
      summary: "",
      recommendations: [],
    },
    termination,
    pendingAction: null,
    counters: {
      passes: findings.length,
      cycles: 0,
      toolCalls: findings.length,
      duplicateRejections: 0,
    },
    ...overrides,
  };
  return state;
}
