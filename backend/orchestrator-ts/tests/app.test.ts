import { afterEach, describe, expect, it } from "vitest";

import { createApp } from "../src/app.js";
import { loadConfig, type AppConfig } from "../src/config.js";
import { createLogger } from "../src/logger.js";
import type { AnalysisRunner, AnalysisResponse } from "../src/pipeline/types.js";
import { startServer, tempReportsDir, type TestServer } from "./helpers/server.js";

const servers: TestServer[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

function makeConfig(overrides: Record<string, string> = {}): AppConfig {
  return loadConfig({
    NODE_ENV: "test",
    REPORTS_DIR: tempReportsDir(),
    ...overrides,
  });
}

export function makeApp(options: {
  config?: AppConfig;
  runner?: AnalysisRunner;
}) {
  const config = options.config ?? makeConfig();
  const logger = createLogger(config);
  const runner: AnalysisRunner =
    options.runner ??
    ({
      async run(): Promise<AnalysisResponse> {
        throw new Error("runner not configured for this test");
      },
    });
  return createApp({ config, runner, logger });
}

describe("http shell", () => {
  it("serves the legacy health payload", async () => {
    const server = await startServer(makeApp({}));
    servers.push(server);

    const response = await fetch(`${server.baseUrl}/api/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      status: "healthy",
      service: "secflow-orchestrator",
    });
  });

  it("reports not ready without a model key", async () => {
    const server = await startServer(makeApp({}));
    servers.push(server);

    const response = await fetch(`${server.baseUrl}/api/ready`);
    expect(response.status).toBe(503);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("not_ready");
    expect(body.checks).toEqual({ model: false, reports: true });
  });

  it("reports ready when the model key and reports dir are available", async () => {
    const server = await startServer(makeApp({ config: makeConfig({ OPENROUTER_API_KEY: "test-key" }) }));
    servers.push(server);

    const response = await fetch(`${server.baseUrl}/api/ready`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.status).toBe("ready");
    expect(body.checks).toEqual({ model: true, reports: true });
  });

  it("sets permissive CORS headers and answers preflight", async () => {
    const server = await startServer(makeApp({}));
    servers.push(server);

    const response = await fetch(`${server.baseUrl}/api/health`, {
      method: "OPTIONS",
      headers: { Origin: "http://localhost:5173" },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("returns a JSON 404 for unknown routes", async () => {
    const server = await startServer(makeApp({}));
    servers.push(server);

    const response = await fetch(`${server.baseUrl}/api/nope`);
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "Not found" });
  });
});
