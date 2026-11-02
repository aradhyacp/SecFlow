import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { analyzerToolResultSchema } from "../../src/analyzers/schema.js";
import { createAnalyzerToolRegistry } from "../../src/analyzers/tools.js";
import { loadConfig } from "../../src/config.js";
import { makeTargetId } from "../../src/graph/ids.js";
import { InMemoryRawOutputStore } from "../../src/graph/rawOutputStore.js";
import type { AnalysisTarget } from "../../src/graph/state.js";
import type { ToolContext } from "../../src/graph/tools.js";
import { createLogger } from "../../src/logger.js";

const enabled = process.env.SECFLOW_LIVE_ANALYZERS === "1";
const describeLive = enabled ? describe : describe.skip;

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const EXAMPLES = {
  malware: path.join(REPO_ROOT, "examples/RealMalware.exe"),
  macro: path.join(REPO_ROOT, "examples/nuclear_motor_example.docm"),
  steg: path.join(REPO_ROOT, "backend/Steg-Analyzer/example/example1.png"),
} as const;

/**
 * Step 6 live gate. Requires the analyzer services to be running:
 *
 *   SECFLOW_LIVE_ANALYZERS=1 npm test
 *
 * Host-port defaults match backend/compose.yml. Override any service with
 * ANALYZER_<NAME>_URL.
 */
function liveConfig() {
  return loadConfig({
    NODE_ENV: "test",
    LOG_LEVEL: "silent",
    ANALYZER_MALWARE_URL:
      process.env.ANALYZER_MALWARE_URL ?? "http://127.0.0.1:5001/api/malware-analyzer",
    ANALYZER_STEG_URL: process.env.ANALYZER_STEG_URL ?? "http://127.0.0.1:5002/api/steg-analyzer",
    ANALYZER_RECON_URL:
      process.env.ANALYZER_RECON_URL ?? "http://127.0.0.1:5003/api/Recon-Analyzer",
    ANALYZER_WEB_URL: process.env.ANALYZER_WEB_URL ?? "http://127.0.0.1:5005/api/web-analyzer",
    ANALYZER_MACRO_URL:
      process.env.ANALYZER_MACRO_URL ?? "http://127.0.0.1:5006/api/macro-analyzer",
    ANALYZER_TIMEOUT_MS: process.env.ANALYZER_TIMEOUT_MS ?? "180000",
    ANALYZER_MAX_RETRIES: "0",
  });
}

function targetFor(
  kind: AnalysisTarget["kind"],
  value: string,
  displayName: string,
): AnalysisTarget {
  return {
    id: makeTargetId(kind, value),
    kind,
    value,
    displayName,
    origin: "user_input",
  };
}

function contextFor(targets: AnalysisTarget[]): ToolContext {
  return {
    runId: "live-analyzer-integration",
    pass: 1,
    targets: new Map(targets.map((target) => [target.id, target])),
    rawOutputStore: new InMemoryRawOutputStore(),
  };
}

async function runTool(
  tool: Parameters<ReturnType<typeof createAnalyzerToolRegistry>["execute"]>[0],
  target: AnalysisTarget,
) {
  const config = liveConfig();
  const registry = createAnalyzerToolRegistry(config, createLogger(config));
  const result = await registry.execute(tool, { targetId: target.id }, contextFor([target]));
  expect(result.ok).toBe(true);
  if (!result.ok) {
    throw new Error(`${tool} failed: ${result.error}`);
  }
  return analyzerToolResultSchema.parse(result.output);
}

describeLive("live analyzer APIs", () => {
  it("malware-analyzer /file-analysis + /decompile", async () => {
    const target = targetFor("file", EXAMPLES.malware, "RealMalware.exe");
    const parsed = await runTool("analyze_malware", target);
    expect(parsed.secFlow.analyzer).toBe("malware");
    expect(parsed.secFlow.pass).toBe(1);
    expect(parsed.secFlow.raw_output.length).toBeGreaterThan(0);
    expect(parsed.secFlow.findings.length).toBeGreaterThan(0);
  }, 300_000);

  it("steg-analyzer upload → status → result", async () => {
    const target = targetFor("file", EXAMPLES.steg, "example1.png");
    const parsed = await runTool("analyze_steg", target);
    expect(parsed.secFlow.analyzer).toBe("steg");
    expect(parsed.secFlow.raw_output.length).toBeGreaterThan(0);
  }, 360_000);

  it("recon-analyzer /scan", async () => {
    const target = targetFor("ip", "8.8.8.8", "8.8.8.8");
    const parsed = await runTool("analyze_recon", target);
    expect(parsed.secFlow.analyzer).toBe("recon");
    expect(parsed.secFlow.findings.length).toBeGreaterThan(0);
  }, 120_000);

  it("web-analyzer aggregated routes", async () => {
    const value = "https://example.com";
    const target = targetFor("url", value, value);
    const parsed = await runTool("analyze_web", target);
    expect(parsed.secFlow.analyzer).toBe("web");
    expect(parsed.secFlow.raw_output).toContain("Web analysis for");
  }, 180_000);

  it("macro-analyzer /analyze", async () => {
    const target = targetFor("file", EXAMPLES.macro, "nuclear_motor_example.docm");
    const parsed = await runTool("analyze_macro", target);
    expect(parsed.secFlow.analyzer).toBe("macro");
    expect(parsed.secFlow.raw_output.length).toBeGreaterThan(0);
  }, 180_000);
});
