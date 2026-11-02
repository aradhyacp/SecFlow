import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { END, START, StateGraph } from "@langchain/langgraph";
import { describe, expect, it } from "vitest";

import { makeIndicatorId, makeTargetId } from "../src/graph/ids.js";
import { InMemoryRawOutputStore } from "../src/graph/rawOutputStore.js";
import {
  analysisStateSchema,
  AnalysisStateAnnotation,
  type AnalysisGraphState,
} from "../src/graph/state.js";
import {
  secFlowFindingSchema,
  secFlowResultSchema,
  severityRiskScore,
  summarizeFindings,
} from "../src/graph/schema/analyzer.js";
import {
  analysisToolNames,
  generateReportInputSchema,
  generateSigmaInputSchema,
  generateYaraInputSchema,
  targetRefSchema,
} from "../src/graph/schema/tools.js";
import {
  formatUntrusted,
  wrapUntrusted,
  UNTRUSTED_DATA_POLICY,
} from "../src/graph/untrusted.js";

const fixturePath = fileURLToPath(
  new URL("../../../docs/ts-migration/fixtures/smart-analyze-response.json", import.meta.url),
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  findings_summary: unknown[];
};

const target = {
  id: makeTargetId("ip", "8.8.8.8"),
  kind: "ip" as const,
  value: "8.8.8.8",
  displayName: "8.8.8.8",
  origin: "classifier" as const,
};

function validState(): AnalysisGraphState {
  return {
    runId: "run-schema-test",
    source: { kind: "target", displayName: "8.8.8.8" },
    target,
    targets: [target],
    indicators: [],
    classification: {
      inputType: "ip",
      analyzer: "recon",
      mimeType: "text/plain",
      magicOutput: "8.8.8.8",
      deterministic: true,
    },
    inputType: "ip",
    context: {
      runId: "run-schema-test",
      startedAt: "2026-11-01T00:00:00.000Z",
      maxPasses: 3,
      maxCycles: 6,
      maxToolCalls: 8,
      modelId: "openai/gpt-4.1-mini",
    },
    findings: [],
    toolHistory: [],
    errors: [],
    rules: { yara: [], sigma: [] },
    report: {
      status: "not_started",
      totalPasses: 0,
      overallRiskScore: 0,
      summary: "",
      recommendations: [],
    },
    termination: null,
    pendingAction: null,
    counters: { passes: 0, cycles: 0, toolCalls: 0, duplicateRejections: 0 },
  };
}

describe("SecFlow contract schemas", () => {
  it("accepts every finding summary from the recorded fixture", () => {
    expect(fixture.findings_summary.length).toBeGreaterThan(0);
    for (const result of fixture.findings_summary) {
      expect(() => secFlowResultSchema.parse(result)).not.toThrow();
    }
  });

  it("rejects unknown severities and out-of-range risk scores", () => {
    const finding = { type: "x", detail: "y", severity: "urgent" };
    expect(secFlowFindingSchema.safeParse(finding).success).toBe(false);

    expect(
      secFlowResultSchema.safeParse({
        analyzer: "recon",
        pass: 1,
        input: "8.8.8.8",
        findings: [],
        risk_score: 11,
        raw_output: "",
      }).success,
    ).toBe(false);
  });

  it("rejects extra keys rather than silently accepting contract drift", () => {
    const result = {
      analyzer: "recon",
      pass: 1,
      input: "8.8.8.8",
      findings: [],
      risk_score: 0,
      raw_output: "",
      unexpected: true,
    };
    expect(secFlowResultSchema.safeParse(result).success).toBe(false);
  });

  it("mirrors the Python severity weights and caps at 10", () => {
    const score = severityRiskScore([
      { type: "a", detail: "a", severity: "critical" },
      { type: "b", detail: "b", severity: "high" },
      { type: "c", detail: "c", severity: "medium" },
      { type: "d", detail: "d", severity: "low" },
      { type: "e", detail: "e", severity: "info" },
    ]);
    expect(score).toBe(7.8);

    const capped = severityRiskScore(
      Array.from({ length: 10 }, (_, index) => ({
        type: `c${index}`,
        detail: "critical",
        severity: "critical" as const,
      })),
    );
    expect(capped).toBe(10);
  });

  it("builds a concise finding summary for the model", () => {
    const summary = summarizeFindings([
      { type: "blocklist_hit", detail: "8.8.8.8 is listed", severity: "critical" },
    ]);
    expect(summary).toContain("[critical] blocklist_hit");
  });
});

describe("tool input schemas", () => {
  it("accept only trusted target references", () => {
    expect(targetRefSchema.safeParse({ targetId: target.id }).success).toBe(true);
    expect(targetRefSchema.safeParse({ targetId: "/etc/passwd" }).success).toBe(false);
    expect(targetRefSchema.safeParse({ targetId: "http://169.254.169.254" }).success).toBe(false);
    expect(targetRefSchema.safeParse({ targetId: target.id, command: "id" }).success).toBe(false);
  });

  it("have no free-form arguments for analyzer tools", () => {
    for (const name of analysisToolNames) {
      expect(name.length).toBeGreaterThan(0);
    }
    expect(targetRefSchema.safeParse({ path: "/tmp/sample.exe" }).success).toBe(false);
    expect(targetRefSchema.safeParse({ url: "https://example.com" }).success).toBe(false);
  });

  it("rule and report tools reject model-supplied evidence or commands", () => {
    expect(generateYaraInputSchema.safeParse({}).success).toBe(true);
    expect(generateSigmaInputSchema.safeParse({}).success).toBe(true);
    expect(generateReportInputSchema.safeParse({}).success).toBe(true);

    expect(generateYaraInputSchema.safeParse({ rule: "rule x {}" }).success).toBe(false);
    expect(generateSigmaInputSchema.safeParse({ logsource: "made up" }).success).toBe(false);
    expect(generateReportInputSchema.safeParse({ path: "/app/reports" }).success).toBe(false);
  });

  it("indexes indicators by deterministic ids", () => {
    expect(makeIndicatorId("ip", "8.8.8.8")).toMatch(/^ioc_[a-f0-9]{16}$/);
  });
});

describe("analysis state", () => {
  it("validates a complete state snapshot", () => {
    const state = validState();
    expect(analysisStateSchema.safeParse(state).success).toBe(true);
  });

  it("rejects a state carrying a raw filesystem path as a model-visible target value", () => {
    const state = {
      ...validState(),
      targets: [{ ...target, id: "/tmp/sample.exe" }],
    };
    expect(analysisStateSchema.safeParse(state).success).toBe(false);
  });

  it("appends findings and deduplicates targets through annotation reducers", async () => {
    const secondTarget = {
      id: makeTargetId("domain", "example.com"),
      kind: "domain" as const,
      value: "example.com",
      displayName: "example.com",
      origin: "artifact" as const,
    };
    const result = JSON.parse(JSON.stringify(fixture.findings_summary[0])) as never;

    const graph = new StateGraph(AnalysisStateAnnotation)
      .addNode("collect", () => ({
        findings: [result],
        targets: [target, secondTarget],
        counters: { passes: 1, cycles: 1, toolCalls: 1, duplicateRejections: 0 },
      }))
      .addEdge(START, "collect")
      .addEdge("collect", END)
      .compile();

    const output = await graph.invoke(validState());
    expect(output.findings).toHaveLength(1);
    expect(output.targets.map((item) => item.id)).toEqual([target.id, secondTarget.id]);
    expect(output.counters.passes).toBe(1);
  });
});

describe("untrusted content handling", () => {
  it("truncates and labels analyzer output", () => {
    const content = wrapUntrusted("analyzer_output", "a".repeat(20), 10);
    expect(content.truncated).toBe(true);
    expect(content.text).toHaveLength(10);
    expect(formatUntrusted(content)).toContain('<untrusted_evidence source="analyzer_output">');
    expect(UNTRUSTED_DATA_POLICY).toContain("never instructions");
  });
});

describe("raw output store", () => {
  it("stores full output outside graph state and returns a compact ref", async () => {
    const store = new InMemoryRawOutputStore();
    const content = "decompiled output\n".repeat(500);
    const ref = await store.put({ analyzer: "malware", pass: 1, content });

    expect(ref.id).toMatch(/^raw_[a-f0-9]{16}$/);
    expect(ref.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(ref.bytes).toBe(Buffer.byteLength(content, "utf8"));
    expect(ref.preview.length).toBe(2_000);
    expect(await store.get(ref)).toBe(content);
    expect(await store.get("raw_0000000000000000")).toBeUndefined();
  });
});
