import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { finalizeAnalysis } from "../src/graph/finalize.js";
import type { SecFlowResult } from "../src/graph/schema/analyzer.js";
import { ToolRegistry } from "../src/graph/tools.js";
import { createReportTool } from "../src/report/tools.js";
import { createRuleGenerationTools } from "../src/rules/tools.js";
import { makeState } from "./helpers/analysisState.js";
import { ScriptedObjectModel } from "./helpers/generationModel.js";

const VALID_YARA = `rule SecFlow_Test_Payload {
  meta:
    description = "test payload indicator"
    author = "SecFlow"
    date = "2026-11-01"
  strings:
    $a = "payload.exe" ascii wide
  condition:
    any of them
}`;

const VALID_SIGMA = `title: SecFlow Suspicious Payload Download
id: 123e4567-e89b-42d3-a456-426614174000
status: experimental
description: Detects the observed payload hostname.
author: SecFlow
date: 2026/11/01
modified: 2026/11/01
tags:
  - attack.execution
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: 'recongraph.xyz'
  condition: selection
falsepositives:
  - Unknown
level: high
`;

const YARA_DRAFT = {
  reasoning: "Concrete file content is present in the macro evidence.",
  rules: [
    {
      rule_name: "SecFlow_Test_Payload",
      description: "Detects payload.exe from the macro IOC.",
      reasoning: "Derived from macro:pass1:finding2.",
      tags: ["malware"],
      evidence_refs: ["macro:pass1:finding2"],
      rule_text: VALID_YARA,
    },
  ],
};

const SIGMA_DRAFT = {
  reasoning: "Concrete network IOCs are present in the macro evidence.",
  rules: [
    {
      rule_name: "SecFlow Suspicious Payload Download",
      description: "Detects the observed hostname.",
      log_source: "proxy",
      reasoning: "Derived from macro:pass1:finding2.",
      tags: ["attack.execution"],
      evidence_refs: ["macro:pass1:finding2"],
      rule_text: VALID_SIGMA,
    },
  ],
};

function infoOnly(): SecFlowResult[] {
  return [
    {
      analyzer: "recon",
      pass: 1,
      input: "8.8.8.8",
      findings: [
        {
          type: "geolocation",
          detail: "IP geolocation: country=US, ISP=Example",
          severity: "info",
        },
      ],
      risk_score: 0,
      raw_output: "clean",
    },
  ];
}

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function registryFor(model: ScriptedObjectModel, reportsDir: string): Promise<ToolRegistry> {
  const now = () => new Date("2026-11-01T00:06:00.000Z");
  return new ToolRegistry([
    ...createRuleGenerationTools({ model, now }),
    createReportTool({ reportsDir, now }),
  ]);
}

describe("post-analysis finalize stage", () => {
  it("generates validated YARA/SIGMA rules and the final report", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-finalize-"));
    tempDirs.push(dir);
    const model = new ScriptedObjectModel([YARA_DRAFT, SIGMA_DRAFT]);
    const registry = await registryFor(model, dir);
    const state = makeState();

    const result = await finalizeAnalysis({
      state,
      registry,
      jobId: "0123456789abcdef",
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(result.report.status).toBe("generated");
    expect(result.report.overallRiskScore).toBe(9.5);
    expect(result.report.jsonPath).toContain("0123456789abcdef");
    expect(await readFile(result.report.jsonPath!, "utf8")).toContain("invoice.docm");
    expect(await readFile(result.report.htmlPath!, "utf8")).toContain("SecFlow Threat Analysis");
    expect(result.rules.yara).toHaveLength(1);
    expect(result.rules.yara[0]?.status).toBe("valid");
    expect(result.rules.sigma).toHaveLength(1);
    expect(result.rules.sigma[0]?.status).toBe("valid");
    expect(result.rules.skipReason).toBeUndefined();
    expect(result.toolHistory.map((entry) => entry.tool)).toEqual([
      "analyze_macro",
      "analyze_recon",
      "analyze_web",
      "generate_yara",
      "generate_sigma",
      "generate_report",
    ]);
    expect(result.termination?.reason).toBe("model_finished");
  });

  it("skips both rule stages with explicit reasons when evidence is insufficient", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-finalize-"));
    tempDirs.push(dir);
    const model = new ScriptedObjectModel([]);
    const registry = await registryFor(model, dir);
    const state = makeState({ indicators: [] }, infoOnly());

    const result = await finalizeAnalysis({
      state,
      registry,
      jobId: "1122334455667788",
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(model.requests).toHaveLength(0);
    expect(result.rules.yara).toEqual([]);
    expect(result.rules.sigma).toEqual([]);
    expect(result.rules.skipReason).toContain("YARA:");
    expect(result.rules.skipReason).toContain("SIGMA:");
    expect(result.report.status).toBe("generated");
  });

  it("records generation failures but still builds the report", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-finalize-"));
    tempDirs.push(dir);
    const model = new ScriptedObjectModel([]);
    const registry = await registryFor(model, dir);

    const result = await finalizeAnalysis({
      state: makeState(),
      registry,
      jobId: "2233445566778899",
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(result.rules.yara).toEqual([]);
    expect(result.rules.sigma).toEqual([]);
    expect(result.errors.map((error) => error.code)).toContain("generate_yara_validation");
    expect(result.errors.map((error) => error.code)).toContain("generate_sigma_validation");
    expect(result.report.status).toBe("generated");
    expect(result.toolHistory.filter((entry) => entry.status === "failed")).toHaveLength(2);
  });

  it("returns a skipped report when no analyzer findings exist", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-finalize-"));
    tempDirs.push(dir);
    const model = new ScriptedObjectModel([]);
    const registry = await registryFor(model, dir);

    const result = await finalizeAnalysis({
      state: makeState({}, []),
      registry,
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(result.report.status).toBe("skipped");
    expect(result.report.totalPasses).toBe(0);
    expect(result.report.error).toContain("No analyzer findings");
  });

  it("records a missing generation registry without crashing", async () => {
    const result = await finalizeAnalysis({
      state: makeState(),
      registry: new ToolRegistry([]),
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(result.report.status).toBe("failed");
    expect(result.errors.map((error) => error.code)).toContain("generate_yara_unavailable");
    expect(result.errors.map((error) => error.code)).toContain("generate_report_unavailable");
  });
});
