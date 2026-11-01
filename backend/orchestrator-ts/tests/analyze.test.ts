import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { createLogger } from "../src/logger.js";
import { createAnalysisRunner } from "../src/pipeline/index.js";
import type { AnalysisRunner, AnalysisRequest, AnalysisResponse } from "../src/pipeline/types.js";
import { startServer, tempReportsDir, type TestServer } from "./helpers/server.js";

const servers: TestServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

const REPORT_ID = "9f2c4a1b7d3e5f60";

function fakeResponse(): AnalysisResponse {
  return {
    jobId: REPORT_ID,
    passesCompleted: 1,
    overallRiskScore: 4.5,
    findingsSummary: [
      {
        analyzer: "recon",
        pass: 1,
        input: "recongraph.xyz",
        findings: [{ type: "ioc_match", detail: "ThreatFox match", severity: "critical" }],
        risk_score: 4.5,
        raw_output: "threatfox: malware=MintsLoader",
      },
    ],
    reportPaths: {
      json: `/app/reports/${REPORT_ID}/report.json`,
      html: `/app/reports/${REPORT_ID}/report.html`,
    },
    reportUrls: {
      json: `/api/report/${REPORT_ID}/json`,
      html: `/api/report/${REPORT_ID}/html`,
    },
  };
}

function recordingRunner(requests: AnalysisRequest[]): AnalysisRunner {
  return {
    async run(request: AnalysisRequest): Promise<AnalysisResponse> {
      requests.push(request);
      return fakeResponse();
    },
  };
}

async function appWithRunner(runner: AnalysisRunner) {
  const config = loadConfig({ NODE_ENV: "test", REPORTS_DIR: tempReportsDir() });
  const app = createApp({ config, runner, logger: createLogger(config) });
  const server = await startServer(app);
  servers.push(server);
  return { server, config };
}

describe("POST /api/smart-analyze", () => {
  it("returns the legacy snake_case response contract", async () => {
    const requests: AnalysisRequest[] = [];
    const { server } = await appWithRunner(recordingRunner(requests));

    const response = await fetch(`${server.baseUrl}/api/smart-analyze?passes=3`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target: "recongraph.xyz" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      job_id: REPORT_ID,
      passes_completed: 1,
      overall_risk_score: 4.5,
      findings_summary: fakeResponse().findingsSummary,
      report_paths: fakeResponse().reportPaths,
      report_urls: fakeResponse().reportUrls,
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]?.maxPasses).toBe(3);
    expect(requests[0]?.input.kind).toBe("target");
    expect(requests[0]?.input.value).toBe("recongraph.xyz");
    expect(requests[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  it("accepts url and query aliases", async () => {
    const requests: AnalysisRequest[] = [];
    const { server } = await appWithRunner(recordingRunner(requests));

    for (const body of [{ url: "https://example.org" }, { query: "8.8.8.8" }]) {
      const response = await fetch(`${server.baseUrl}/api/smart-analyze`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
    }

    expect(requests.map((request) => request.input.value)).toEqual([
      "https://example.org",
      "8.8.8.8",
    ]);
  });

  it("defaults non-numeric passes to 3", async () => {
    const requests: AnalysisRequest[] = [];
    const { server } = await appWithRunner(recordingRunner(requests));

    const response = await fetch(`${server.baseUrl}/api/smart-analyze?passes=abc`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target: "8.8.8.8" }),
    });

    expect(response.status).toBe(200);
    expect(requests[0]?.maxPasses).toBe(3);
  });

  it("rejects out-of-range pass counts", async () => {
    const { server } = await appWithRunner(recordingRunner([]));

    for (const passes of ["1", "2", "6"]) {
      const response = await fetch(`${server.baseUrl}/api/smart-analyze?passes=${passes}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target: "8.8.8.8" }),
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: "passes must be 3, 4, or 5" });
    }
  });

  it("rejects a JSON body without a target", async () => {
    const { server } = await appWithRunner(recordingRunner([]));

    const response = await fetch(`${server.baseUrl}/api/smart-analyze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "JSON body must contain 'target', 'url', or 'query' field",
    });
  });

  it("rejects unsupported content types", async () => {
    const { server } = await appWithRunner(recordingRunner([]));

    const response = await fetch(`${server.baseUrl}/api/smart-analyze`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "raw",
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "Provide 'file' (multipart/form-data) or 'target' (application/json)",
    });
  });

  it("stores uploads on disk for the runner and removes them afterwards", async () => {
    const requests: AnalysisRequest[] = [];
    let bytesSeenDuringRun = "";

    const runner: AnalysisRunner = {
      async run(request: AnalysisRequest): Promise<AnalysisResponse> {
        requests.push(request);
        bytesSeenDuringRun = await readFile(request.input.value, "utf8");
        return fakeResponse();
      },
    };
    const { server } = await appWithRunner(runner);

    const form = new FormData();
    form.append("file", new Blob(["hello secflow"], { type: "application/octet-stream" }), "sample.bin");

    const response = await fetch(`${server.baseUrl}/api/smart-analyze`, {
      method: "POST",
      body: form,
    });

    expect(response.status).toBe(200);
    expect(bytesSeenDuringRun).toBe("hello secflow");
    expect(requests[0]?.input.kind).toBe("file");
    expect(requests[0]?.input.value).toMatch(/sample\.bin$/);

    const uploadedPath = requests[0]?.input.value ?? "";
    await expect(readFile(uploadedPath)).rejects.toThrow();
  });

  it("returns 501 until the graph is wired (step 2 shell)", async () => {
    const config = loadConfig({ NODE_ENV: "test", REPORTS_DIR: tempReportsDir() });
    const runner = createAnalysisRunner(config, createLogger(config));
    const server = await startServer(createApp({ config, runner, logger: createLogger(config) }));
    servers.push(server);

    const response = await fetch(`${server.baseUrl}/api/smart-analyze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target: "8.8.8.8" }),
    });

    expect(response.status).toBe(501);
    expect((await response.json() as { error: string }).error).toMatch(/not implemented/i);
  });
});

describe("GET /api/report/:jobId/:fmt", () => {
  async function appWithReports() {
    const reportsDir = tempReportsDir();
    await mkdir(path.join(reportsDir, REPORT_ID), { recursive: true });
    await writeFile(path.join(reportsDir, REPORT_ID, "report.json"), '{"ok":true}');
    await writeFile(path.join(reportsDir, REPORT_ID, "report.html"), "<html>ok</html>");

    const config = loadConfig({ NODE_ENV: "test", REPORTS_DIR: reportsDir });
    const server = await startServer(
      createApp({ config, runner: recordingRunner([]), logger: createLogger(config) }),
    );
    servers.push(server);
    return server;
  }

  it("serves JSON as an attachment", async () => {
    const server = await appWithReports();
    const response = await fetch(`${server.baseUrl}/api/report/${REPORT_ID}/json`);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("content-disposition")).toContain(
      `secflow_report_${REPORT_ID}.json`,
    );
    expect(await response.text()).toBe('{"ok":true}');
  });

  it("serves HTML inline", async () => {
    const server = await appWithReports();
    const response = await fetch(`${server.baseUrl}/api/report/${REPORT_ID}/html`);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(await response.text()).toBe("<html>ok</html>");
  });

  it("rejects unknown formats", async () => {
    const server = await appWithReports();
    const response = await fetch(`${server.baseUrl}/api/report/${REPORT_ID}/pdf`);
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: "Unknown format 'pdf'. Use json or html.",
    });
  });

  it("rejects non-hex job ids", async () => {
    const server = await appWithReports();
    for (const jobId of ["..%2F..%2Fetc%2Fpasswd", "ABC123", "not-hex"]) {
      const response = await fetch(`${server.baseUrl}/api/report/${jobId}/json`);
      expect([400, 404]).toContain(response.status);
    }
  });

  it("returns 404 for a missing report", async () => {
    const server = await appWithReports();
    const response = await fetch(`${server.baseUrl}/api/report/deadbeefdeadbeef/json`);
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: "Report not found for job_id 'deadbeefdeadbeef'",
    });
  });
});
