import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { createAnalyzerToolRegistry } from "../src/analyzers/tools.js";
import { analyzerToolResultSchema } from "../src/analyzers/schema.js";
import { loadConfig } from "../src/config.js";
import { makeTargetId } from "../src/graph/ids.js";
import { InMemoryRawOutputStore } from "../src/graph/rawOutputStore.js";
import type { AnalysisTarget } from "../src/graph/state.js";
import type { ToolContext } from "../src/graph/tools.js";
import { createLogger } from "../src/logger.js";
import { sendJson, startTestServer, type TestServer } from "./helpers/httpServer.js";

const FIXTURES_DIR = new URL("../../../docs/ts-migration/fixtures/", import.meta.url);
function fixture(name: string): unknown {
  return JSON.parse(readFileSync(fileURLToPath(new URL(name, FIXTURES_DIR)), "utf8"));
}

let server: TestServer;
let tempDir: string;
let registry: ReturnType<typeof createAnalyzerToolRegistry>;
let fileTarget: AnalysisTarget;
let imageTarget: AnalysisTarget;
let macroTarget: AnalysisTarget;
let ipTarget: AnalysisTarget;
let emailTarget: AnalysisTarget;
let urlTarget: AnalysisTarget;

const webFixture = fixture("web-aggregated.json") as Record<string, unknown>;

const WEB_HEALTHY_PATHS: Record<string, string> = {
  status: "status",
  "security-headers": "security_headers",
  tls: "tls",
  ssl: "ssl",
  hsts: "hsts",
  firewall: "firewall",
  redirects: "redirects",
  headers: "headers",
  "redirect-chain": "redirect_chain",
  "malware-check": "malware_check",
  "url-parse": "url_parse",
  dns: "dns",
};

beforeAll(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "secflow-tools-test-"));
  const binaryPath = path.join(tempDir, "sample.bin");
  const imagePath = path.join(tempDir, "image.png");
  const macroPath = path.join(tempDir, "invoice.docm");
  await writeFile(binaryPath, Buffer.from([0x4d, 0x5a, 0x00, 0x01]));
  await writeFile(imagePath, Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  await writeFile(macroPath, Buffer.from("PK\u0003\u0004mock docm"));

  server = await startTestServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://localhost");
    const pathname = requestUrl.pathname;

    if (request.method === "POST" && pathname.endsWith("/malware-analyzer/file-analysis")) {
      sendJson(response, 200, fixture("malware-file-analysis.json"));
      return;
    }
    if (request.method === "POST" && pathname.endsWith("/malware-analyzer/decompile")) {
      sendJson(response, 200, fixture("malware-decompile.json"));
      return;
    }
    if (request.method === "POST" && pathname.endsWith("/steg-analyzer/upload")) {
      sendJson(response, 200, { submission_hash: "abc123" });
      return;
    }
    if (request.method === "GET" && pathname.endsWith("/steg-analyzer/status/abc123")) {
      sendJson(response, 200, { status: "completed" });
      return;
    }
    if (request.method === "GET" && pathname.endsWith("/steg-analyzer/result/abc123")) {
      sendJson(response, 200, fixture("steg-result.json"));
      return;
    }
    if (request.method === "POST" && pathname.endsWith("/Recon-Analyzer/scan")) {
      sendJson(response, 200, fixture("recon-scan.json"));
      return;
    }
    if (request.method === "POST" && pathname.endsWith("/Recon-Analyzer/footprint")) {
      sendJson(response, 200, fixture("recon-footprint-email.json"));
      return;
    }
    if (request.method === "POST" && pathname.endsWith("/macro-analyzer/analyze")) {
      sendJson(response, 200, fixture("macro-analyze.json"));
      return;
    }
    if (request.method === "GET" && pathname.startsWith("/api/web-analyzer/")) {
      const route = pathname.slice("/api/web-analyzer/".length);
      const key = WEB_HEALTHY_PATHS[route];
      if (key && key in webFixture) {
        sendJson(response, 200, webFixture[key]);
        return;
      }
    }

    sendJson(response, 404, { error: `no test route for ${request.method} ${pathname}` });
  });

  const config = loadConfig({
    NODE_ENV: "test",
    LOG_LEVEL: "silent",
    ANALYZER_MALWARE_URL: `${server.baseUrl}/api/malware-analyzer`,
    ANALYZER_STEG_URL: `${server.baseUrl}/api/steg-analyzer`,
    ANALYZER_RECON_URL: `${server.baseUrl}/api/Recon-Analyzer`,
    ANALYZER_WEB_URL: `${server.baseUrl}/api/web-analyzer`,
    ANALYZER_MACRO_URL: `${server.baseUrl}/api/macro-analyzer`,
    ANALYZER_TIMEOUT_MS: "5000",
    ANALYZER_MAX_RETRIES: "0",
    ALLOW_PRIVATE_TARGETS: "1",
  });
  const logger = createLogger(config);
  registry = createAnalyzerToolRegistry(config, logger);

  fileTarget = {
    id: makeTargetId("file", binaryPath),
    kind: "file",
    value: binaryPath,
    displayName: "sample.bin",
    origin: "user_input",
  };
  imageTarget = {
    id: makeTargetId("file", imagePath),
    kind: "file",
    value: imagePath,
    displayName: "image.png",
    origin: "user_input",
  };
  macroTarget = {
    id: makeTargetId("file", macroPath),
    kind: "file",
    value: macroPath,
    displayName: "invoice.docm",
    origin: "user_input",
  };
  ipTarget = {
    id: makeTargetId("ip", "8.8.8.8"),
    kind: "ip",
    value: "8.8.8.8",
    displayName: "8.8.8.8",
    origin: "classifier",
  };
  emailTarget = {
    id: makeTargetId("email", "user@example.com"),
    kind: "email",
    value: "user@example.com",
    displayName: "user@example.com",
    origin: "classifier",
  };
  urlTarget = {
    id: makeTargetId("url", "https://example.com"),
    kind: "url",
    value: "https://example.com",
    displayName: "https://example.com",
    origin: "classifier",
  };
});

afterAll(async () => {
  await server.close();
  await rm(tempDir, { recursive: true, force: true });
});

function context(targets: AnalysisTarget[], store = new InMemoryRawOutputStore()): ToolContext {
  return {
    runId: "run-tools-test",
    pass: 1,
    targets: new Map(targets.map((target) => [target.id, target])),
    rawOutputStore: store,
  };
}

describe("analyzer tools against a fixture-backed HTTP service", () => {
  it("runs the malware tool and keeps full output out of the model result", async () => {
    const store = new InMemoryRawOutputStore();
    const result = await registry.execute(
      "analyze_malware",
      { targetId: fileTarget.id },
      context([fileTarget, imageTarget, macroTarget, ipTarget, emailTarget, urlTarget], store),
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const parsed = analyzerToolResultSchema.parse(result.output);

    expect(parsed.secFlow).toMatchObject({
      analyzer: "malware",
      pass: 1,
      input: "sample.bin",
      risk_score: 10,
    });
    expect(parsed.secFlow.findings).toHaveLength(11);
    expect(parsed.secFlow.raw_output).toContain("Ghidra decompiled");

    expect(parsed.modelOutput.rawOutputRef.id).toMatch(/^raw_[a-f0-9]{16}$/);
    expect(parsed.modelOutput.findings.length).toBeLessThanOrEqual(50);
    expect(parsed.modelOutput.rawOutputRef.preview.length).toBeLessThanOrEqual(2_000);
    for (const finding of parsed.modelOutput.findings) {
      expect(finding.detail.length).toBeLessThanOrEqual(500);
      expect(finding.evidence?.length ?? 0).toBeLessThanOrEqual(500);
    }
    const modelJson = JSON.stringify(parsed.modelOutput);
    expect(modelJson).not.toContain('"raw_output"');
    expect(modelJson.length).toBeLessThan(40_000);
    expect(await store.get(parsed.modelOutput.rawOutputRef)).toBe(parsed.secFlow.raw_output);

    const modelProjection = registry.toModelOutput("analyze_malware", result.output);
    expect(modelProjection).toEqual(parsed.modelOutput);
    expect(modelProjection).not.toHaveProperty("secFlow");
  });

  it("runs the steg tool through upload → status → result", async () => {
    const result = await registry.execute(
      "analyze_steg",
      { targetId: imageTarget.id },
      context([imageTarget]),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const parsed = analyzerToolResultSchema.parse(result.output);
    expect(parsed.secFlow).toMatchObject({ analyzer: "steg", risk_score: 5 });
    expect(parsed.secFlow.extracted_files).toEqual(["/download/abc123/binwalk/embedded.zip"]);
  });

  it("selects /scan for an IP and /footprint for an email", async () => {
    const scan = await registry.execute(
      "analyze_recon",
      { targetId: ipTarget.id },
      context([ipTarget]),
    );
    expect(scan.ok).toBe(true);
    if (scan.ok) {
      const parsed = analyzerToolResultSchema.parse(scan.output);
      expect(parsed.secFlow).toMatchObject({ analyzer: "recon", risk_score: 4 });
      expect(parsed.secFlow.findings.map((finding) => finding.type)).toContain("ioc_match");
    }

    const footprint = await registry.execute(
      "analyze_recon",
      { targetId: emailTarget.id },
      context([emailTarget]),
    );
    expect(footprint.ok).toBe(true);
    if (footprint.ok) {
      const parsed = analyzerToolResultSchema.parse(footprint.output);
      expect(parsed.secFlow.findings.map((finding) => finding.type)).toContain("email_breach");
    }
  });

  it("runs all twelve web routes and aggregates the findings", async () => {
    const result = await registry.execute(
      "analyze_web",
      { targetId: urlTarget.id },
      context([urlTarget]),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const parsed = analyzerToolResultSchema.parse(result.output);
    expect(parsed.secFlow).toMatchObject({ analyzer: "web", risk_score: 9.8 });
  });

  it("runs the macro tool", async () => {
    const result = await registry.execute(
      "analyze_macro",
      { targetId: macroTarget.id },
      context([macroTarget]),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const parsed = analyzerToolResultSchema.parse(result.output);
    expect(parsed.secFlow).toMatchObject({ analyzer: "macro", risk_score: 9.5 });
  });

  it("rejects an unknown target id without calling any service", async () => {
    const before = server.requests.length;
    const result = await registry.execute(
      "analyze_web",
      { targetId: "tgt_0000000000000000" },
      context([urlTarget]),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.kind).toBe("execution");
      expect(result.error).toContain("Unknown targetId");
      expect(result.error).toContain(urlTarget.id);
    }
    expect(server.requests.length).toBe(before);
  });

  it("rejects a valid target id of the wrong kind", async () => {
    const before = server.requests.length;
    const result = await registry.execute(
      "analyze_web",
      { targetId: fileTarget.id },
      context([fileTarget]),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain('cannot analyze target kind "file"');
    }
    expect(server.requests.length).toBe(before);
  });
});
