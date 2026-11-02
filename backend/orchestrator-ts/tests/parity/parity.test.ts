import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createApp } from "../../src/app.js";
import { classifyString } from "../../src/classifier/index.js";
import { loadConfig } from "../../src/config.js";
import { runAnalysisLoop } from "../../src/graph/analysis.js";
import { makeTargetId } from "../../src/graph/ids.js";
import { InMemoryRawOutputStore } from "../../src/graph/rawOutputStore.js";
import { createLogger } from "../../src/logger.js";
import type { PayloadDownloader } from "../../src/pipeline/payloadDownloader.js";
import type {
  AnalysisResponse,
  AnalysisRunner,
  ResolvedInput,
  SecFlowResult,
} from "../../src/pipeline/types.js";
import { buildReport } from "../../src/report/build.js";
import { pwndocReportSchema } from "../../src/report/schema.js";
import { choose, finish, ScriptedDecisionModel } from "../helpers/decisionModel.js";
import { createFakeAnalyzerRegistry } from "../helpers/fakeAnalyzers.js";
import { startServer } from "../helpers/server.js";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const FIXTURES_PATH = fileURLToPath(new URL("./fixtures.json", import.meta.url));
const DRIVER_PATH = fileURLToPath(new URL("./python_driver.py", import.meta.url));
const fixedNow = () => new Date("2026-11-02T00:00:00.000Z");

interface ResultTemplate {
  findings: Array<{
    type: string;
    detail: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    evidence?: string;
  }>;
  risk_score: number;
  raw_output: string;
}

interface ScenarioInput {
  kind: "target" | "file";
  value?: string;
  displayName?: string;
  suffix?: string;
  bytesHex?: string;
  bytesBase64?: string;
}

interface Decision {
  action: "finish" | "analyze_recon";
  target?: string;
  reasoning?: string;
}

interface Scenario {
  name: string;
  input: ScenarioInput;
  firstAnalyzer?: string;
  mimeType?: string;
  magicOutput?: string;
  expectedAnalyzers: string[];
  decisions: Decision[];
  download?: {
    url: string;
    contentType: string;
    extension: string;
  };
  failAnalyzer?: string;
  expectedDifference?: "error_semantics";
}

interface Fixtures {
  results: Record<string, ResultTemplate>;
  scenarios: Scenario[];
}

interface PythonScenarioResult {
  name: string;
  input: string;
  displayName: string;
  inputKind: string;
  jobId: string;
  analyzers: string[];
  totalPasses: number;
  overallRiskScore: number;
  findings: Array<Record<string, unknown>>;
  report: {
    input: string;
    total_passes: number;
    overall_risk_score: number;
    passes: Array<{
      pass_number: number;
      analyzer: string;
      findings: Array<Record<string, unknown>>;
    }>;
  };
  reportValid: boolean;
  downloadAttempts: string[];
  downloadSuccesses: string[];
  downloadsCleaned: boolean;
}

interface PythonOutput {
  pythonVersion: string;
  scenarios: PythonScenarioResult[];
  api: {
    healthStatus: number;
    healthBody: unknown;
    analyzeStatus: number;
    analyzeBody: {
      job_id: string;
      passes_completed: number;
      overall_risk_score: number;
      findings_summary: SecFlowResult[];
      report_paths: { json: string; html: string };
      report_urls: { json: string; html: string };
    };
  };
}

const parityEnabled = process.env.SECFLOW_PARITY === "1";
/**
 * The baseline was removed after Step 11. The fixture/driver remain for
 * historical reproduction from a pre-cutover checkout; skip cleanly instead of
 * failing when the retired Python service is absent.
 */
const baselineAvailable = existsSync(
  path.join(REPO_ROOT, "backend", "orchestrator", "app", "__init__.py"),
);
const describeParity = parityEnabled && baselineAvailable ? describe : describe.skip;

if (parityEnabled && !baselineAvailable) {
  console.warn(
    "SECFLOW_PARITY=1 ignored: backend/orchestrator is not present in this checkout. " +
      "Restore the pre-cutover commit to replay Python vs TypeScript parity.",
  );
}

const tempDirs: string[] = [];
let fixtures: Fixtures;
let pythonOutput: PythonOutput;

const ANALYZER_BY_TOOL: Record<string, string> = {
  analyze_malware: "malware",
  analyze_steg: "steg",
  analyze_recon: "recon",
  analyze_web: "web",
  analyze_macro: "macro",
};

function stripInput(findings: Array<Record<string, unknown>>): Array<Record<string, unknown>> {
  return findings.map((finding) => {
    const clone = structuredClone(finding);
    delete clone.input;
    return clone;
  });
}

function scenarioInput(scenario: Scenario, filePath: string): ResolvedInput {
  if (scenario.input.kind === "target") {
    const value = scenario.input.value ?? "";
    return {
      kind: "target",
      value,
      displayName: value,
      cleanup: async () => undefined,
    };
  }
  return {
    kind: "file",
    value: filePath,
    displayName: scenario.input.displayName ?? path.basename(filePath),
    originalName: scenario.input.displayName ?? path.basename(filePath),
    cleanup: async () => undefined,
  };
}

function decisionTargetId(decision: Decision, scenario: Scenario): string {
  const value = decision.target ?? scenario.input.value ?? "";
  const classified = classifyString(value);
  return makeTargetId(classified?.inputType ?? "unknown", value);
}

function modelFor(scenario: Scenario): ScriptedDecisionModel {
  const decisions = scenario.decisions.map((decision) => {
    if (decision.action === "finish") {
      return finish(decision.reasoning);
    }
    return choose(decision.action, decisionTargetId(decision, scenario), decision.reasoning);
  });
  return new ScriptedDecisionModel(decisions);
}

function analyzerResult(scenario: Scenario, analyzer: string, fixture: Fixtures) {
  if (scenario.failAnalyzer === analyzer) {
    throw new Error("synthetic analyzer failure");
  }
  const template = fixture.results[analyzer];
  if (!template) {
    throw new Error(`No parity fixture for analyzer ${analyzer}`);
  }
  return {
    findings: structuredClone(template.findings),
    riskScore: template.risk_score,
    rawOutput: template.raw_output,
  };
}

function inputBytes(scenario: Scenario): Buffer {
  if (scenario.input.bytesBase64) {
    return Buffer.from(scenario.input.bytesBase64, "base64");
  }
  if (scenario.input.bytesHex) {
    return Buffer.from(scenario.input.bytesHex, "hex");
  }
  return Buffer.from("secflow parity sample");
}

describeParity("Step 11 Python vs TypeScript replay", () => {
  beforeAll(async () => {
    fixtures = JSON.parse(await readFile(FIXTURES_PATH, "utf8")) as Fixtures;
    const outputDir = await mkdtemp(path.join(os.tmpdir(), "secflow-parity-output-"));
    tempDirs.push(outputDir);
    const outputPath = path.join(outputDir, "python.json");
    const python =
      process.env.SECFLOW_PARITY_PYTHON ?? path.join(REPO_ROOT, ".venv", "bin", "python");
    if (!existsSync(python)) {
      throw new Error(
        `Python interpreter not found at ${python}. Set SECFLOW_PARITY_PYTHON to run the parity suite.`,
      );
    }

    const child = spawnSync(python, [DRIVER_PATH, FIXTURES_PATH, outputPath], {
      cwd: REPO_ROOT,
      env: { ...process.env, GROQ_API_KEY: "", OPENAI_API_KEY: "" },
      encoding: "utf8",
      timeout: 120_000,
    });
    if (child.status !== 0) {
      throw new Error(
        `Python parity driver failed (status ${child.status}):\n${child.stdout}\n${child.stderr}`,
      );
    }
    pythonOutput = JSON.parse(await readFile(outputPath, "utf8")) as PythonOutput;
  });

  afterAll(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("replays every representative input through both pipelines", async () => {
    expect(pythonOutput.scenarios).toHaveLength(fixtures.scenarios.length);

    for (const scenario of fixtures.scenarios) {
      const py = pythonOutput.scenarios.find((candidate) => candidate.name === scenario.name);
      expect(py, `missing Python scenario ${scenario.name}`).toBeDefined();
      if (!py) {
        continue;
      }

      const workDir = await mkdtemp(path.join(os.tmpdir(), `secflow-ts-parity-${scenario.name}-`));
      tempDirs.push(workDir);
      const filePath = path.join(
        workDir,
        `${scenario.input.kind === "file" ? "input" : "unused"}${scenario.input.suffix ?? ""}`,
      );
      if (scenario.input.kind === "file") {
        await writeFile(filePath, inputBytes(scenario));
      }

      const fake = createFakeAnalyzerRegistry((tool) =>
        analyzerResult(scenario, ANALYZER_BY_TOOL[tool] ?? "", fixtures),
      );
      const model = modelFor(scenario);
      const downloadSpec = scenario.download;
      const downloadedPaths: string[] = [];
      const downloadAttempts: string[] = [];
      const downloadSuccesses: string[] = [];
      let cleanupCalls = 0;
      const downloader: PayloadDownloader = {
        async download(url) {
          downloadAttempts.push(url);
          if (!downloadSpec || url !== downloadSpec.url) {
            throw new Error(`unexpected download URL ${url}`);
          }
          downloadSuccesses.push(url);
          const targetPath = path.join(
            workDir,
            `payload-${downloadedPaths.length}${downloadSpec.extension}`,
          );
          await writeFile(targetPath, "MZ synthetic downloaded payload");
          downloadedPaths.push(targetPath);
          return {
            url,
            path: targetPath,
            contentType: downloadSpec.contentType,
            sizeBytes: 31,
          };
        },
        async cleanup() {
          cleanupCalls += 1;
          await Promise.all(downloadedPaths.map((target) => rm(target, { force: true })));
        },
      };

      const result = await runAnalysisLoop({
        input: scenarioInput(scenario, filePath),
        model,
        tools: fake.registry,
        runId: `parity-${scenario.name}`,
        maxPasses: 3,
        maxCycles: 12,
        maxToolCalls: 20,
        rawOutputStore: new InMemoryRawOutputStore(),
        guard: { assertTargetAllowed: async () => undefined },
        payloadDownloader: downloader,
      });

      if (scenario.expectedDifference === "error_semantics") {
        // Python converts an analyzer exception into a low-severity error
        // finding and continues. The TS graph records the failure in structured
        // tool history/errors and does not fabricate an analyzer result.
        expect(py.findings[0]?.findings).toEqual([
          expect.objectContaining({ type: "error", severity: "low" }),
        ]);
        expect(result.state.findings).toHaveLength(0);
        expect(result.state.errors).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ code: "execution_failure", recoverable: true }),
          ]),
        );
        expect(result.state.toolHistory[0]).toMatchObject({
          tool: "analyze_recon",
          status: "failed",
        });
        continue;
      }

      expect(result.state.findings.map((finding) => finding.analyzer)).toEqual(
        scenario.expectedAnalyzers,
      );
      expect(result.state.findings.map((finding) => finding.analyzer)).toEqual(py.analyzers);
      expect(stripInput(result.state.findings as unknown as Array<Record<string, unknown>>)).toEqual(
        stripInput(py.findings),
      );
      expect(result.state.findings.length).toBe(py.totalPasses);

      const report = buildReport(result.state, fixedNow().toISOString());
      const parsed = pwndocReportSchema.safeParse(report);
      expect(parsed.success).toBe(true);
      expect(py.reportValid).toBe(true);
      expect(report.total_passes).toBe(py.report.total_passes);
      expect(report.overall_risk_score).toBe(py.report.overall_risk_score);
      expect(
        report.passes.map((pass) => ({
          pass_number: pass.pass_number,
          analyzer: pass.analyzer,
          findings: stripInput(pass.findings as unknown as Array<Record<string, unknown>>),
        })),
      ).toEqual(py.report.passes);

      if (scenario.input.kind === "target") {
        expect(report.input).toBe(py.report.input);
        const jobId = createHash("sha256").update(scenario.input.value ?? "").digest("hex").slice(0, 16);
        expect(jobId).toBe(py.jobId);
      } else {
        expect(report.input).toBe(scenario.input.displayName);
        expect(py.report.input.endsWith(scenario.input.displayName ?? "")).toBe(true);
      }

      expect(downloadAttempts).toEqual(py.downloadAttempts);
      expect(downloadSuccesses).toEqual(py.downloadSuccesses);
      await downloader.cleanup();
      expect(cleanupCalls).toBe(1);
      for (const targetPath of downloadedPaths) {
        await expect(access(targetPath)).rejects.toThrow();
      }
      expect(py.downloadsCleaned).toBe(true);
    }
  });

  it("matches the legacy HTTP response contract", async () => {
    const api = pythonOutput.api;
    const reportsDir = await mkdtemp(path.join(os.tmpdir(), "secflow-parity-reports-"));
    tempDirs.push(reportsDir);
    const config = loadConfig({ NODE_ENV: "test", REPORTS_DIR: reportsDir });
    const response: AnalysisResponse = {
      jobId: api.analyzeBody.job_id,
      passesCompleted: api.analyzeBody.passes_completed,
      overallRiskScore: api.analyzeBody.overall_risk_score,
      findingsSummary: api.analyzeBody.findings_summary,
      reportPaths: {
        json: path.join(reportsDir, "report.json"),
        html: path.join(reportsDir, "report.html"),
      },
      reportUrls: api.analyzeBody.report_urls,
    };
    const runner: AnalysisRunner = {
      async run(): Promise<AnalysisResponse> {
        return response;
      },
    };
    const server = await startServer(
      createApp({ config, runner, logger: createLogger(config) }),
    );
    try {
      const health = await fetch(`${server.baseUrl}/api/health`);
      expect(health.status).toBe(api.healthStatus);
      expect(await health.json()).toEqual(api.healthBody);

      const analyze = await fetch(`${server.baseUrl}/api/smart-analyze?passes=3`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target: "8.8.8.8" }),
      });
      expect(analyze.status).toBe(api.analyzeStatus);
      const body = (await analyze.json()) as typeof api.analyzeBody;
      body.report_paths = {
        json: path.basename(body.report_paths.json),
        html: path.basename(body.report_paths.html),
      };
      expect(body).toEqual(api.analyzeBody);
    } finally {
      await server.close();
    }
  });

  it("records the reviewed error-representation difference", () => {
    const scenario = pythonOutput.scenarios.find(
      (candidate) => candidate.name === "analyzer-error",
    );
    expect(scenario?.findings).toHaveLength(1);
    expect(scenario?.findings[0]?.findings).toEqual([
      expect.objectContaining({ type: "error", severity: "low" }),
    ]);
  });
});
