import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { loadConfig } from "../src/config.js";
import { createLogger } from "../src/logger.js";
import { createAnalysisRunner, type RunnerDependencies } from "../src/pipeline/index.js";
import type { PayloadDownloader } from "../src/pipeline/payloadDownloader.js";
import type { AnalysisRequest, ResolvedInput } from "../src/pipeline/types.js";
import { SsrfBlockedError } from "../src/security/networkGuard.js";
import { choose, finish, ScriptedDecisionModel } from "./helpers/decisionModel.js";
import { createFakeAnalyzerRegistry, findingSet } from "./helpers/fakeAnalyzers.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function makeConfig(overrides: Record<string, string> = {}) {
  const reportsDir = await mkdtemp(path.join(os.tmpdir(), "secflow-pipeline-"));
  tempDirs.push(reportsDir);
  return loadConfig({
    NODE_ENV: "test",
    LOG_LEVEL: "silent",
    REPORTS_DIR: reportsDir,
    ...overrides,
  });
}

function targetInput(value: string): ResolvedInput {
  return {
    kind: "target",
    value,
    displayName: value,
    cleanup: async () => undefined,
  };
}

function request(input: ResolvedInput, signal = AbortSignal.timeout(30_000)): AnalysisRequest {
  const config = { logLevel: "silent", env: "test" as const };
  return {
    input,
    maxPasses: 3,
    runId: "run-pipeline-test",
    signal,
    logger: createLogger(config),
  };
}

function dependencies(model: ScriptedDecisionModel, overrides: Partial<RunnerDependencies> = {}) {
  const fake = createFakeAnalyzerRegistry(() => findingSet("country=US, ISP=Example"));
  return {
    payloadDownloader: null,
    ...overrides,
    model,
    analyzerRegistry: fake.registry,
    reportModel: null,
    fake,
  };
}

describe("production analysis runner", () => {
  it("runs the graph, finalizes a report, and returns the legacy response shape", async () => {
    const config = await makeConfig();
    const model = new ScriptedDecisionModel([finish("No external artifacts were found.")]);
    const deps = dependencies(model);
    const runner = createAnalysisRunner(config, createLogger(config), deps);
    const input = targetInput("8.8.8.8");

    const result = await runner.run(request(input));

    expect(deps.fake.calls.map((call) => call.tool)).toEqual(["analyze_recon"]);
    expect(result).toMatchObject({
      jobId: createHash("sha256").update("8.8.8.8").digest("hex").slice(0, 16),
      passesCompleted: 1,
      overallRiskScore: 1,
      reportUrls: {
        json: `/api/report/${createHash("sha256").update("8.8.8.8").digest("hex").slice(0, 16)}/json`,
        html: `/api/report/${createHash("sha256").update("8.8.8.8").digest("hex").slice(0, 16)}/html`,
      },
    });
    expect(result.findingsSummary).toHaveLength(1);
    expect(result.findingsSummary[0]).toMatchObject({ analyzer: "recon", pass: 1 });
    expect(result.reportPaths.json).toContain(result.jobId);
    expect(result.reportPaths.html).toContain(result.jobId);

    const report = JSON.parse(await readFile(result.reportPaths.json, "utf8")) as {
      input: string;
      total_passes: number;
      overall_risk_score: number;
    };
    expect(report).toMatchObject({
      input: "8.8.8.8",
      total_passes: 1,
      overall_risk_score: 1,
    });
    expect(await readFile(result.reportPaths.html, "utf8")).toContain("SecFlow Threat Analysis");
  });

  it("returns 500 instead of a report when every analyzer is unavailable", async () => {
    const config = await makeConfig();
    const model = new ScriptedDecisionModel([finish()]);
    const fake = createFakeAnalyzerRegistry(() => {
      throw new Error("analyzer timeout");
    });
    const runner = createAnalysisRunner(config, createLogger(config), {
      model,
      analyzerRegistry: fake.registry,
      reportModel: null,
    });

    await expect(runner.run(request(targetInput("8.8.8.8")))).rejects.toMatchObject({
      name: "HttpError",
      status: 500,
      message: "Pipeline produced no findings",
    });
    expect(model.requests).toHaveLength(0);
    expect(fake.calls).toHaveLength(1);
  });

  it("maps an expired total-run signal to a 504", async () => {
    const config = await makeConfig();
    const model = new ScriptedDecisionModel([]);
    const deps = dependencies(model);
    const runner = createAnalysisRunner(config, createLogger(config), deps);

    await expect(
      runner.run(request(targetInput("8.8.8.8"), AbortSignal.abort())),
    ).rejects.toMatchObject({ name: "HttpError", status: 504 });
  });

  it("stops before finalization when the total-run deadline expires mid-analysis", async () => {
    const config = await makeConfig();
    const model = new ScriptedDecisionModel([]);
    const fake = createFakeAnalyzerRegistry(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
      return findingSet("country=US, ISP=Example");
    });
    const runner = createAnalysisRunner(config, createLogger(config), {
      model,
      analyzerRegistry: fake.registry,
      reportModel: null,
    });

    await expect(
      runner.run(request(targetInput("8.8.8.8"), AbortSignal.timeout(10))),
    ).rejects.toMatchObject({ name: "HttpError", status: 504 });
    expect(fake.calls).toHaveLength(1);
  });

  it("cleans up run-scoped payload downloads after the run", async () => {
    const config = await makeConfig();
    const model = new ScriptedDecisionModel([finish()]);
    let cleanupCalls = 0;
    const downloader: PayloadDownloader = {
      async download() {
        throw new Error("no download should occur in this test");
      },
      async cleanup() {
        cleanupCalls += 1;
      },
    };
    const runner = createAnalysisRunner(
      config,
      createLogger(config),
      dependencies(model, { payloadDownloader: downloader }),
    );

    await runner.run(request(targetInput("8.8.8.8")));

    expect(cleanupCalls).toBe(1);
  });

  it("blocks an SSRF target before any analyzer executes", async () => {
    const config = await makeConfig();
    const model = new ScriptedDecisionModel([]);
    const deps = dependencies(model);
    const runner = createAnalysisRunner(config, createLogger(config), deps);

    await expect(
      runner.run(request(targetInput("http://127.0.0.1:8080/admin"))),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
    expect(deps.fake.calls).toHaveLength(0);
    expect(model.requests).toHaveLength(0);
  });

  it("uses analyzer tool/target allowlisting on a model-selected follow-up", async () => {
    const config = await makeConfig();
    const fake = createFakeAnalyzerRegistry((tool) => {
      if (tool === "analyze_web") {
        return {
          findings: [
            {
              type: "embedded_payload",
              detail: "Page references a payload host",
              severity: "medium",
              evidence: "https://payload.example/dropper.exe",
            },
          ],
          riskScore: 3,
          rawOutput: "https://payload.example/dropper.exe",
        };
      }
      return findingSet("country=US, ISP=Example");
    });
    const urlId = `tgt_${createHash("sha256").update("url\u0000https://payload.example/dropper.exe").digest("hex").slice(0, 16)}`;
    const model = new ScriptedDecisionModel([
      choose("analyze_web", urlId, "The web pass exposed a concrete payload URL."),
      finish(),
    ]);
    const runner = createAnalysisRunner(config, createLogger(config), {
      model,
      analyzerRegistry: fake.registry,
      reportModel: null,
      payloadDownloader: null,
    });

    const result = await runner.run(request(targetInput("https://start.example")));

    expect(fake.calls.map((call) => call.tool)).toEqual(["analyze_web", "analyze_web"]);
    expect(result.passesCompleted).toBe(2);
  });
});
