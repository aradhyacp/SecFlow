import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { makeRuleId } from "../src/graph/ids.js";
import type { RuleArtifact } from "../src/graph/schema/rules.js";
import { buildReport } from "../src/report/build.js";
import { pwndocReportSchema } from "../src/report/schema.js";
import { createReportTool } from "../src/report/tools.js";
import { fixtureFindings, makeState } from "./helpers/analysisState.js";
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

function rule(
  kind: "yara" | "sigma",
  content: string,
  status: RuleArtifact["status"],
  name: string,
): RuleArtifact {
  return {
    id: makeRuleId(kind, content),
    kind,
    name,
    description: `${kind} test rule`,
    tags: [kind],
    content,
    reasoning: "Derived from recorded analyzer evidence.",
    status,
    validationErrors: status === "invalid" ? ["synthetic validation error"] : [],
    evidenceRefs: ["macro:pass1:finding2"],
    createdAt: "2026-11-01T00:06:00.000Z",
  };
}

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("report builder", () => {
  it("builds a contract-valid report from the recorded fixture state", () => {
    const state = makeState();
    const report = buildReport(state, "2026-11-01T00:06:00.000Z");
    const parsed = pwndocReportSchema.safeParse(report);

    expect(parsed.success).toBe(true);
    expect(report.input).toBe("invoice.docm");
    expect(report.input).not.toContain("/tmp/");
    expect(report.total_passes).toBe(3);
    expect(report.overall_risk_score).toBe(9.5);
    expect(report.passes.map((pass) => pass.analyzer)).toEqual(["macro", "recon", "web"]);
    expect(report.analyzers_executed).toEqual(["macro", "recon", "web"]);
    expect(report.recommendations.length).toBeGreaterThan(0);
    expect(report.limitations?.join(" ")).toContain("not been manually validated");
    expect(report.tools).toHaveLength(3);
    expect(report.timestamps?.started_at).toBe("2026-11-01T00:00:00.000Z");
  });

  it("includes deployable rules in the legacy threat_intel shape and rejects invalid rules there", () => {
    const validYara = rule("yara", VALID_YARA, "valid", "SecFlow_Test_Payload");
    const validSigma = rule("sigma", VALID_SIGMA, "valid", "SecFlow Suspicious Payload Download");
    const invalidSigma = rule("sigma", "title: broken", "invalid", "Broken rule");
    const state = makeState({
      rules: { yara: [validYara], sigma: [validSigma, invalidSigma] },
    });
    const report = buildReport(state, "2026-11-01T00:06:00.000Z");

    expect(report.threat_intel?.yara?.total_rules).toBe(1);
    expect(report.threat_intel?.sigma?.total_rules).toBe(1);
    expect(report.threat_intel?.sigma?.rules[0]?.rule_name).toBe(
      "SecFlow Suspicious Payload Download",
    );
    expect(report.rules?.sigma).toHaveLength(2);
    expect(report.limitations?.join(" ")).toContain("failed validation");
    expect(pwndocReportSchema.safeParse(report).success).toBe(true);
  });
});

describe("report tool", () => {
  it("writes JSON and HTML reports under the trusted job id", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-report-"));
    tempDirs.push(dir);
    const state = makeState({
      rules: {
        yara: [rule("yara", VALID_YARA, "valid", "SecFlow_Test_Payload")],
        sigma: [],
      },
    });
    const tool = createReportTool({
      reportsDir: dir,
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    const result = await tool.execute(
      {},
      { runId: "run-report-test", jobId: "0123456789abcdef", state },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.error);
    }
    const output = result.output as {
      status: string;
      jsonPath: string;
      htmlPath: string;
      overallRiskScore: number;
    };
    expect(output.status).toBe("generated");
    expect(output.overallRiskScore).toBe(9.5);
    expect(output.jsonPath).toBe(path.join(dir, "0123456789abcdef", "report.json"));
    expect(output.htmlPath).toBe(path.join(dir, "0123456789abcdef", "report.html"));

    const json = JSON.parse(await readFile(output.jsonPath, "utf8")) as unknown;
    expect(pwndocReportSchema.safeParse(json).success).toBe(true);
    const html = await readFile(output.htmlPath, "utf8");
    expect(html).toContain("SecFlow Threat Analysis");
    expect(html).toContain("YARA rules");
    expect(html).toContain("invoice.docm");
  });

  it("uses the optional model narrative without changing the report contract", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-report-"));
    tempDirs.push(dir);
    const state = makeState();
    const model = new ScriptedObjectModel([
      {
        summary: "Model-written executive summary grounded in the recorded findings.",
        recommendations: ["Quarantine the document.", "Block the observed hostname."],
      },
    ]);
    const tool = createReportTool({
      reportsDir: dir,
      model,
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    const result = await tool.execute(
      {},
      { runId: "run-report-test", jobId: "abcdefabcdefabcd", state },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.error);
    }
    const output = result.output as { jsonPath: string };
    const json = JSON.parse(await readFile(output.jsonPath, "utf8")) as {
      summary: string;
      recommendations: string[];
    };
    expect(json.summary).toContain("Model-written");
    expect(json.recommendations).toEqual([
      "Quarantine the document.",
      "Block the observed hostname.",
    ]);
    expect(model.requests).toHaveLength(1);
    expect(model.requests[0]?.prompt).toContain("<untrusted_evidence");
  });

  it("escapes untrusted finding content in HTML", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-report-"));
    tempDirs.push(dir);
    const findings = fixtureFindings();
    findings.push({
      analyzer: "web",
      pass: 4,
      input: "https://recongraph.xyz",
      findings: [
        {
          type: "reflected_content",
          detail: "<script>alert('xss')</script>",
          severity: "high",
          evidence: "<img src=x onerror=alert(1)>",
        },
      ],
      risk_score: 5,
      raw_output: "reflected content",
    });
    const state = makeState({}, findings);
    const tool = createReportTool({ reportsDir: dir });
    const result = await tool.execute(
      {},
      { runId: "run-report-test", jobId: "fedcba9876543210", state },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.error);
    }
    const output = result.output as { htmlPath: string };
    const html = await readFile(output.htmlPath, "utf8");
    expect(html).not.toContain("<script>alert('xss')</script>");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("returns an explicit skipped result when there are no findings", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "secflow-report-"));
    tempDirs.push(dir);
    const state = makeState({}, []);
    const tool = createReportTool({ reportsDir: dir });
    const result = await tool.execute(
      {},
      { runId: "run-report-test", jobId: "0011223344556677", state },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.error);
    }
    expect(result.output).toMatchObject({
      status: "skipped",
      overallRiskScore: 0,
      recommendations: [],
    });
  });
});
