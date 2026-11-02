import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { runAnalysisLoop } from "../src/graph/analysis.js";
import { InMemoryRawOutputStore } from "../src/graph/rawOutputStore.js";
import { makeTargetId } from "../src/graph/ids.js";
import type { PayloadDownloader } from "../src/pipeline/payloadDownloader.js";
import type { PassCount, ResolvedInput } from "../src/pipeline/types.js";
import { choose, finish, ScriptedDecisionModel } from "./helpers/decisionModel.js";
import { createFakeAnalyzerRegistry, findingSet } from "./helpers/fakeAnalyzers.js";

const RUN_ID = "run-analysis-loop-test";
const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function targetInput(value: string): ResolvedInput {
  return {
    kind: "target",
    value,
    displayName: value,
    cleanup: async () => undefined,
  };
}

function options(
  model: ScriptedDecisionModel,
  registry: ReturnType<typeof createFakeAnalyzerRegistry>["registry"],
  overrides: { maxPasses?: PassCount; maxCycles?: number; maxToolCalls?: number } = {},
) {
  return {
    model,
    tools: registry,
    runId: RUN_ID,
    maxPasses: overrides.maxPasses ?? 3,
    maxCycles: overrides.maxCycles ?? 12,
    maxToolCalls: overrides.maxToolCalls ?? 20,
    rawOutputStore: new InMemoryRawOutputStore(),
  };
}

describe("analysis decision loop", () => {
  it("runs the deterministic first analyzer without asking the model", async () => {
    const { registry, calls } = createFakeAnalyzerRegistry(() => ({
      ...findingSet("geo finding"),
      rawOutput: "related domain evil.example",
    }));
    const model = new ScriptedDecisionModel([finish("No external artifacts were found.")]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput("8.8.8.8"),
    });

    expect(result.status).toBe("completed");
    expect(calls.map((call) => call.tool)).toEqual(["analyze_recon"]);
    expect(calls[0]?.pass).toBe(1);
    expect(model.requests).toHaveLength(1);
    expect(model.requests[0]?.maxOutputTokens).toBeGreaterThanOrEqual(2_048);
    expect(result.state.findings).toHaveLength(1);
    expect(result.state.findings[0]).toMatchObject({
      analyzer: "recon",
      pass: 1,
      input: "8.8.8.8",
      risk_score: 1,
    });
    expect(result.state.termination).toMatchObject({
      reason: "model_finished",
      detail: "No external artifacts were found.",
    });
  });

  it("shows only target-compatible tools to the model", async () => {
    const { registry } = createFakeAnalyzerRegistry(() => ({
      findings: [],
      riskScore: 0,
      rawOutput: "found 8.8.8.8",
    }));
    const model = new ScriptedDecisionModel([finish()]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput("https://start.example"),
    });

    expect(result.status).toBe("completed");
    const request = model.requests[0];
    expect(request?.prompt).toContain("analyze_recon");
    expect(request?.prompt).not.toContain("analyze_malware");
    expect(
      request?.schema.safeParse({
        action: "analyze_web",
        targetId: makeTargetId("ip", "8.8.8.8"),
        reasoning: "wrong tool",
      }).success,
    ).toBe(false);
  });

  it("extracts artifacts and runs a model-selected follow-up pass", async () => {
    const { registry, calls } = createFakeAnalyzerRegistry((tool) => {
      if (tool === "analyze_web") {
        return {
          findings: [
            {
              type: "embedded_payload",
              detail: "Page references a downloadable executable",
              severity: "medium",
              evidence: "https://payload.example/dropper.exe",
            },
          ],
          riskScore: 3,
          rawOutput: "web references https://payload.example/dropper.exe and resolves to 8.8.8.8",
        };
      }
      return findingSet("IP reputation finding");
    });

    const ipId = makeTargetId("ip", "8.8.8.8");
    const model = new ScriptedDecisionModel([
      choose("analyze_recon", ipId, "A concrete IP was found in the web evidence."),
      finish("The extracted IP has been analyzed."),
    ]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput("https://start.example"),
    });

    expect(result.status).toBe("completed");
    expect(calls.map((call) => call.tool)).toEqual(["analyze_web", "analyze_recon"]);
    expect(calls.map((call) => call.pass)).toEqual([1, 2]);
    expect(result.state.findings).toHaveLength(2);
    expect(result.state.findings[1]?.analyzer).toBe("recon");
    expect(result.state.targets.map((target) => `${target.kind}:${target.value}`)).toContain(
      "ip:8.8.8.8",
    );
    expect(result.state.targets.map((target) => `${target.kind}:${target.value}`)).toContain(
      "url:https://payload.example/dropper.exe",
    );
    expect(
      result.state.indicators.map((indicator) => `${indicator.kind}:${indicator.value}`),
    ).toContain("ip:8.8.8.8");
    expect(model.requests[1]?.prompt).toContain(ipId);
    expect(model.requests[1]?.prompt).toContain("8.8.8.8");
  });

  it("rejects a repeated tool/target pair", async () => {
    const { registry, calls } = createFakeAnalyzerRegistry(() => ({
      findings: [],
      riskScore: 0,
      rawOutput: "found 8.8.8.8",
    }));
    const urlId = makeTargetId("url", "https://start.example");
    const model = new ScriptedDecisionModel(
      [choose("analyze_web", urlId, "Repeat the same scan.")],
      false,
    );

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput("https://start.example"),
    });

    expect(result.status).toBe("stopped");
    expect(result.state.termination?.reason).toBe("duplicate_analysis");
    expect(calls.map((call) => call.tool)).toEqual(["analyze_web"]);
    expect(result.state.errors.at(-1)?.code).toBe("duplicate_action");
  });

  it("stops at the model-cycle budget", async () => {
    const { registry, calls } = createFakeAnalyzerRegistry((tool) => ({
      findings: [],
      riskScore: 0,
      rawOutput:
        tool === "analyze_web" ? "links: https://a.example https://b.example" : "no new artifacts",
    }));
    const first = makeTargetId("url", "https://a.example");
    const second = makeTargetId("url", "https://b.example");
    const model = new ScriptedDecisionModel([
      choose("analyze_web", first),
      choose("analyze_web", second),
    ]);

    const result = await runAnalysisLoop({
      ...options(model, registry, { maxCycles: 2, maxPasses: 5 }),
      input: targetInput("https://start.example"),
    });

    expect(result.status).toBe("stopped");
    expect(result.state.termination?.reason).toBe("max_cycles");
    expect(model.requests).toHaveLength(2);
    expect(calls).toHaveLength(3);
  });

  it("stops at the configured pass budget", async () => {
    const { registry, calls } = createFakeAnalyzerRegistry((tool) => ({
      findings: [],
      riskScore: 0,
      rawOutput:
        tool === "analyze_web" ? "links: https://a.example https://b.example" : "no new artifacts",
    }));
    const model = new ScriptedDecisionModel([
      choose("analyze_web", makeTargetId("url", "https://a.example")),
      choose("analyze_web", makeTargetId("url", "https://b.example")),
    ]);

    const result = await runAnalysisLoop({
      ...options(model, registry, { maxPasses: 3 }),
      input: targetInput("https://start.example"),
    });

    expect(result.status).toBe("stopped");
    expect(result.state.termination?.reason).toBe("max_passes");
    expect(result.state.counters.passes).toBe(3);
    expect(calls).toHaveLength(3);
    expect(model.requests).toHaveLength(2);
  });

  it("records an analyzer failure without crashing the loop", async () => {
    const { registry } = createFakeAnalyzerRegistry(() => {
      throw new Error("service exploded");
    });
    const model = new ScriptedDecisionModel([finish()]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput("8.8.8.8"),
    });

    expect(result.status).toBe("completed");
    expect(result.state.termination?.reason).toBe("no_artifacts");
    expect(result.state.findings).toHaveLength(0);
    expect(result.state.toolHistory[0]).toMatchObject({
      tool: "analyze_recon",
      status: "failed",
    });
    expect(result.state.errors[0]?.code).toBe("execution_failure");
    expect(model.requests).toHaveLength(0);
  });

  it("falls back to model-selected recon for an unknown string", async () => {
    const value = "plain words that are not an indicator";
    const { registry, calls } = createFakeAnalyzerRegistry(() => findingSet("username footprint"));
    const model = new ScriptedDecisionModel([
      choose("analyze_recon", makeTargetId("unknown", value), "The input may be a username."),
      finish("The footprint pass completed."),
    ]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput(value),
    });

    expect(result.status).toBe("completed");
    expect(calls.map((call) => call.tool)).toEqual(["analyze_recon"]);
    expect(result.state.findings).toHaveLength(1);
    expect(result.state.target.kind).toBe("unknown");
    expect(model.requests).toHaveLength(1);
    expect(model.requests[0]?.prompt).toContain("plain words that are not an indicator");
  });

  it("offers all file analyzers for an unknown upload", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "secflow-unknown-file-"));
    tempDirs.push(tempDir);
    const filePath = path.join(tempDir, "sample.dat");
    await writeFile(filePath, "not a known file signature");

    const { registry, calls } = createFakeAnalyzerRegistry(() => findingSet("synthetic file scan"));
    const model = new ScriptedDecisionModel([
      choose(
        "analyze_malware",
        makeTargetId("file", filePath),
        "The file head is ambiguous, so try the malware analyzer first.",
      ),
      finish("The file pass completed."),
    ]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: {
        kind: "file",
        value: filePath,
        displayName: "sample.dat",
        originalName: "sample.dat",
        sizeBytes: 26,
        cleanup: async () => undefined,
      },
    });

    expect(result.status).toBe("completed");
    expect(calls.map((call) => call.tool)).toEqual(["analyze_malware"]);
    expect(model.requests[0]?.prompt).toContain("Classification preview");
    expect(model.requests[0]?.prompt).toContain("not a known file signature");
    expect(model.requests[0]?.prompt).toContain("analyze_steg");
    expect(model.requests[0]?.prompt).toContain("analyze_macro");
  });

  it("downloads a payload on finish and sends it to the matching file analyzer", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "secflow-payload-loop-"));
    tempDirs.push(tempDir);
    const payloadPath = path.join(tempDir, "dropper.exe");
    await writeFile(payloadPath, "MZ synthetic payload");

    const downloads: string[] = [];
    const downloader: PayloadDownloader = {
      async download(url) {
        downloads.push(url);
        return {
          url,
          path: payloadPath,
          contentType: "application/x-dosexec",
          sizeBytes: 21,
        };
      },
      async cleanup() {
        // The production runner owns cleanup; the graph only selects the target.
      },
    };

    const { registry, calls } = createFakeAnalyzerRegistry((tool) => {
      if (tool === "analyze_web") {
        return {
          findings: [
            {
              type: "embedded_payload",
              detail: "The page links to an executable",
              severity: "medium",
              evidence: "https://payload.example/dropper.exe",
            },
          ],
          riskScore: 3,
          rawOutput: "https://payload.example/dropper.exe",
        };
      }
      return findingSet("PE analysis complete");
    });

    const model = new ScriptedDecisionModel([
      finish("No further network target is useful."),
      finish("The downloaded payload has been analyzed."),
    ]);

    const result = await runAnalysisLoop({
      ...options(model, registry),
      input: targetInput("https://start.example"),
      guard: { assertTargetAllowed: async () => undefined },
      payloadDownloader: downloader,
    });

    expect(result.status).toBe("completed");
    expect(downloads).toEqual(["https://payload.example/dropper.exe"]);
    expect(calls.map((call) => call.tool)).toEqual(["analyze_web", "analyze_malware"]);
    const payloadTarget = result.state.targets.find(
      (target) => target.origin === "payload_download",
    );
    expect(payloadTarget).toMatchObject({
      kind: "file",
      displayName: "dropper.exe",
      sourceUrl: "https://payload.example/dropper.exe",
    });
    const malwareResult = result.state.findings[1];
    expect(malwareResult?.findings[0]).toMatchObject({
      type: "payload_downloaded",
      severity: "high",
      evidence: "https://payload.example/dropper.exe",
    });
    expect(malwareResult?.risk_score).toBe(1);
  });
});
