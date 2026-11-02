import { describe, expect, it } from "vitest";

import { ConfigError, loadConfig } from "../src/config.js";

describe("loadConfig", () => {
  it("applies documented defaults", () => {
    const config = loadConfig({ NODE_ENV: "test" });

    expect(config.port).toBe(5000);
    expect(config.model.modelId).toBe("nvidia/nemotron-3-ultra-550b-a55b:free");
    expect(config.model.maxCycles).toBe(12);
    expect(config.model.maxToolCalls).toBe(20);
    expect(config.model.timeoutMs).toBe(60_000);
    expect(config.analyzerTimeoutMs).toBe(60_000);
    expect(config.analyzerMaxRetries).toBe(1);
    expect(config.totalAnalysisTimeoutMs).toBe(600_000);
    expect(config.analyzers.malware.timeoutOverrideMs).toBeUndefined();
    expect(config.maxUploadBytes).toBe(50 * 1024 * 1024);
    expect(config.allowPrivateTargets).toBe(false);
    expect(config.analyzers.malware.baseUrl).toBe(
      "http://malware-analyzer:5000/api/malware-analyzer",
    );
    expect(config.analyzers.recon.baseUrl).toBe("http://recon-analyzer:5000/api/Recon-Analyzer");
  });

  it("trims trailing slashes from analyzer URLs", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ANALYZER_WEB_URL: "http://web-analyzer:5000/api/web-analyzer///",
    });
    expect(config.analyzers.web.baseUrl).toBe("http://web-analyzer:5000/api/web-analyzer");
  });

  it("supports per-analyzer timeout overrides", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ANALYZER_TIMEOUT_MS: "1000",
      ANALYZER_MALWARE_TIMEOUT_MS: "180000",
    });
    expect(config.analyzers.malware.timeoutMs).toBe(180_000);
    expect(config.analyzers.malware.timeoutOverrideMs).toBe(180_000);
    expect(config.analyzers.web.timeoutMs).toBe(1000);
    expect(config.analyzers.web.timeoutOverrideMs).toBeUndefined();
  });

  it("bounds the analyzer retry budget", () => {
    expect(loadConfig({ NODE_ENV: "test", ANALYZER_MAX_RETRIES: "0" }).analyzerMaxRetries).toBe(0);
    expect(loadConfig({ NODE_ENV: "test", ANALYZER_MAX_RETRIES: "3" }).analyzerMaxRetries).toBe(3);
    expect(() => loadConfig({ NODE_ENV: "test", ANALYZER_MAX_RETRIES: "6" })).toThrow(ConfigError);
    expect(() => loadConfig({ NODE_ENV: "test", ANALYZER_MAX_RETRIES: "-1" })).toThrow(ConfigError);
  });

  it("rejects malformed analyzer URLs", () => {
    expect(() => loadConfig({ NODE_ENV: "test", ANALYZER_WEB_URL: "not-a-url" })).toThrow(
      ConfigError,
    );
  });

  it("requires OPENROUTER_API_KEY in production", () => {
    expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/OPENROUTER_API_KEY/);
  });

  it("allows production boot without a key when explicitly permitted", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      ALLOW_MISSING_OPENROUTER_KEY: "true",
    });
    expect(config.model.apiKey).toBeNull();
  });

  it("parses boolean flags", () => {
    expect(loadConfig({ NODE_ENV: "test", ALLOW_PRIVATE_TARGETS: "1" }).allowPrivateTargets).toBe(
      true,
    );
    expect(
      loadConfig({ NODE_ENV: "test", ALLOW_PRIVATE_TARGETS: "false" }).allowPrivateTargets,
    ).toBe(false);
  });

  it("rejects invalid numeric ranges", () => {
    expect(() => loadConfig({ NODE_ENV: "test", PORT: "70000" })).toThrow(ConfigError);
    expect(() => loadConfig({ NODE_ENV: "test", MODEL_TEMPERATURE: "5" })).toThrow(ConfigError);
  });
});
