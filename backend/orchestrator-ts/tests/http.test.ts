import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AnalyzerHttpError, requestJson } from "../src/analyzers/http.js";
import { sendJson, startTestServer, type TestServer } from "./helpers/httpServer.js";

let server: TestServer;
let flakyCount = 0;

beforeAll(async () => {
  server = await startTestServer((request, response) => {
    const pathname = new URL(request.url ?? "/", "http://localhost").pathname;

    switch (pathname) {
      case "/ok":
        sendJson(response, 200, { value: 42 });
        return;
      case "/slow":
        setTimeout(() => sendJson(response, 200, { value: "late" }), 500);
        return;
      case "/flaky":
        flakyCount += 1;
        if (flakyCount === 1) {
          sendJson(response, 503, { error: "temporarily unavailable" });
          return;
        }
        sendJson(response, 200, { value: "recovered" });
        return;
      case "/bad-request":
        sendJson(response, 400, { error: "invalid input" });
        return;
      case "/invalid-json":
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end("{not json");
        return;
      case "/large":
        response.statusCode = 200;
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify({ value: "x".repeat(8_192) }));
        return;
      case "/network-failure":
        response.destroy();
        return;
      case "/abort":
        setTimeout(() => sendJson(response, 200, { value: "too late" }), 500);
        return;
      default:
        sendJson(response, 404, { error: `no route for ${pathname}` });
    }
  });
});

afterAll(async () => {
  await server.close();
});

describe("requestJson", () => {
  it("returns parsed JSON on success", async () => {
    await expect(
      requestJson(`${server.baseUrl}/ok`, { label: "test", timeoutMs: 1_000 }),
    ).resolves.toEqual({ value: 42 });
  });

  it("aborts a request that exceeds the timeout", async () => {
    const before = server.requests.length;
    await expect(
      requestJson(`${server.baseUrl}/slow`, { label: "test", timeoutMs: 50 }),
    ).rejects.toMatchObject({ name: "TimeoutError" });
    expect(server.requests.length).toBe(before + 1);
  });

  it("retries a transient 503 and then succeeds", async () => {
    flakyCount = 0;
    await expect(
      requestJson(`${server.baseUrl}/flaky`, {
        label: "test",
        timeoutMs: 1_000,
        maxRetries: 1,
        retryDelayMs: 1,
      }),
    ).resolves.toEqual({ value: "recovered" });
    expect(flakyCount).toBe(2);
  });

  it("does not retry a 4xx response", async () => {
    const before = server.requests.length;
    const error = await requestJson(`${server.baseUrl}/bad-request`, {
      label: "test",
      timeoutMs: 1_000,
      maxRetries: 3,
      retryDelayMs: 1,
    }).catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(AnalyzerHttpError);
    expect(error).toMatchObject({ status: 400, retriable: false });
    expect(server.requests.length).toBe(before + 1);
  });

  it("rejects a response body that exceeds the configured cap", async () => {
    const before = server.requests.length;
    const error = await requestJson(`${server.baseUrl}/large`, {
      label: "test",
      timeoutMs: 1_000,
      maxResponseBytes: 128,
    }).catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(AnalyzerHttpError);
    expect(error).toMatchObject({ retriable: false });
    expect((error as AnalyzerHttpError).message).toContain("exceeded 128 bytes");
    expect(server.requests.length).toBe(before + 1);
  });

  it("does not retry invalid JSON", async () => {
    const before = server.requests.length;
    const error = await requestJson(`${server.baseUrl}/invalid-json`, {
      label: "test",
      timeoutMs: 1_000,
      maxRetries: 3,
      retryDelayMs: 1,
    }).catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(AnalyzerHttpError);
    expect(error).toMatchObject({ retriable: false });
    expect((error as AnalyzerHttpError).message).toContain("invalid JSON");
    expect(server.requests.length).toBe(before + 1);
  });

  it("retries network failures up to the bounded maximum", async () => {
    const before = server.requests.length;
    const error = await requestJson(`${server.baseUrl}/network-failure`, {
      label: "test",
      timeoutMs: 1_000,
      maxRetries: 2,
      retryDelayMs: 1,
    }).catch((cause: unknown) => cause);

    expect(error).toBeInstanceOf(Error);
    expect(server.requests.length).toBe(before + 3);
  });

  it("propagates caller aborts without retrying", async () => {
    const controller = new AbortController();
    const before = server.requests.length;
    const pending = requestJson(`${server.baseUrl}/abort`, {
      label: "test",
      timeoutMs: 5_000,
      maxRetries: 3,
      retryDelayMs: 1,
      signal: controller.signal,
    });
    for (let attempt = 0; attempt < 100 && server.requests.length === before; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    controller.abort();

    await expect(pending).rejects.toMatchObject({ name: "AbortError" });
    expect(server.requests.length).toBe(before + 1);
  });
});
