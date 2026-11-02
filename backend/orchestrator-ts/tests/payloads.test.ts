import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { SecFlowResult } from "../src/graph/schema/analyzer.js";
import {
  HttpPayloadDownloader,
  PayloadDownloadError,
  type HttpPayloadDownloaderOptions,
} from "../src/pipeline/payloadDownloader.js";
import {
  ensureAnalyzerFileExtension,
  findPayloadCandidates,
  payloadDisplayName,
  selectAnalyzerForDownload,
  shouldSkipDownloadContentType,
} from "../src/pipeline/payloads.js";
import {
  createNetworkGuard,
  SsrfBlockedError,
  type NetworkGuard,
} from "../src/security/networkGuard.js";
import { startTestServer, type TestHandler, type TestServer } from "./helpers/httpServer.js";

const servers: TestServer[] = [];
const downloaders: HttpPayloadDownloader[] = [];
const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(downloaders.splice(0).map((downloader) => downloader.cleanup()));
  await Promise.all(servers.splice(0).map((server) => server.close()));
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

async function serve(handler: TestHandler): Promise<TestServer> {
  const server = await startTestServer(handler);
  servers.push(server);
  return server;
}

function downloader(options: HttpPayloadDownloaderOptions = {}): HttpPayloadDownloader {
  const instance = new HttpPayloadDownloader(options);
  downloaders.push(instance);
  return instance;
}

const allowPrivate = createNetworkGuard({ allowPrivateTargets: true });

describe("HttpPayloadDownloader", () => {
  it("streams a payload to an extension-preserving temp file and cleans it up", async () => {
    const body = Buffer.from("MZ synthetic executable");
    const server = await serve((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "application/x-dosexec; charset=binary");
      response.end(body);
    });

    const result = await downloader().download(`${server.baseUrl}/dropper.exe`, {
      guard: allowPrivate,
    });

    expect(result.contentType).toBe("application/x-dosexec");
    expect(result.sizeBytes).toBe(body.length);
    expect(path.extname(result.path)).toBe(".exe");
    expect(await readFile(result.path)).toEqual(body);

    const directory = path.dirname(result.path);
    await downloaders[0]?.cleanup();
    await expect(access(result.path)).rejects.toThrow();
    await expect(access(directory)).rejects.toThrow();
  });

  it("checks the SSRF guard on every redirect hop", async () => {
    const server = await serve((request, response) => {
      if (request.url === "/start") {
        response.statusCode = 302;
        response.setHeader("location", "/final.exe");
        response.end();
        return;
      }
      response.statusCode = 200;
      response.setHeader("content-type", "application/octet-stream");
      response.end("payload");
    });
    const checked: string[] = [];
    const guard: NetworkGuard = {
      async assertTargetAllowed(target) {
        checked.push(target.value);
        await allowPrivate.assertTargetAllowed(target);
      },
    };

    const result = await downloader().download(`${server.baseUrl}/start`, { guard });

    expect(result.url).toBe(`${server.baseUrl}/final.exe`);
    expect(checked).toEqual([`${server.baseUrl}/start`, `${server.baseUrl}/final.exe`]);
  });

  it("refuses a redirect whose destination is blocked", async () => {
    const server = await serve((request, response) => {
      if (request.url === "/start") {
        response.statusCode = 302;
        response.setHeader("location", "/private.exe");
        response.end();
        return;
      }
      response.end("should not be reached");
    });
    let checks = 0;
    const guard: NetworkGuard = {
      async assertTargetAllowed() {
        checks += 1;
        if (checks === 2) {
          throw new SsrfBlockedError("Prohibited network target: blocked redirect.");
        }
      },
    };

    await expect(
      downloader().download(`${server.baseUrl}/start`, { guard }),
    ).rejects.toBeInstanceOf(SsrfBlockedError);
    expect(checks).toBe(2);
    expect(server.requests.map((request) => request.url)).toEqual(["/start"]);
  });

  it("rejects a declared Content-Length above the cap", async () => {
    const server = await serve((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "application/octet-stream");
      response.setHeader("content-length", "12");
      response.end(Buffer.alloc(12));
    });

    await expect(
      downloader({ maxBytes: 8 }).download(`${server.baseUrl}/large.bin`, {
        guard: allowPrivate,
      }),
    ).rejects.toMatchObject({ code: "payload_too_large" });
  });

  it("enforces the cap while streaming when no Content-Length is present", async () => {
    const server = await serve((_request, response) => {
      response.statusCode = 200;
      response.setHeader("content-type", "application/octet-stream");
      response.write(Buffer.alloc(6));
      response.end(Buffer.alloc(6));
    });

    await expect(
      downloader({ maxBytes: 8 }).download(`${server.baseUrl}/stream.bin`, {
        guard: allowPrivate,
      }),
    ).rejects.toBeInstanceOf(PayloadDownloadError);
  });

  it("surfaces HTTP failures without writing a file", async () => {
    const server = await serve((_request, response) => {
      response.statusCode = 404;
      response.end("not found");
    });

    await expect(
      downloader().download(`${server.baseUrl}/missing.bin`, { guard: allowPrivate }),
    ).rejects.toMatchObject({ code: "http_error" });
  });
});

describe("payload selection helpers", () => {
  it("prefers known file extensions and skips already-downloaded URLs", () => {
    const result: SecFlowResult = {
      analyzer: "web",
      pass: 1,
      input: "https://start.example",
      findings: [
        {
          type: "link",
          detail: "document and executable links",
          severity: "medium",
          evidence: "https://payload.example/invoice.docx",
        },
      ],
      risk_score: 2,
      raw_output:
        "https://payload.example/page https://payload.example/dropper.exe https://payload.example/invoice.docx",
    };

    expect(
      findPayloadCandidates(result, new Set(["https://payload.example/dropper.exe"])),
    ).toEqual(["https://payload.example/invoice.docx", "https://payload.example/page"]);
  });

  it("selects by content type before extension and skips web pages", () => {
    expect(selectAnalyzerForDownload("https://x.example/file.pdf", "image/png")).toBe("steg");
    expect(selectAnalyzerForDownload("https://x.example/file.docx", "application/pdf")).toBe(
      "macro",
    );
    expect(selectAnalyzerForDownload("https://x.example/file.pdf", "application/pdf")).toBeNull();
    expect(shouldSkipDownloadContentType("text/html; charset=utf-8")).toBe(true);
    expect(shouldSkipDownloadContentType("application/json")).toBe(true);
    expect(shouldSkipDownloadContentType("application/pdf")).toBe(false);
  });

  it("produces safe display names with an analyzer-compatible extension", () => {
    expect(payloadDisplayName("https://x.example/dropper.exe", "malware")).toBe("dropper.exe");
    expect(payloadDisplayName("https://x.example/dropper.exe", "macro")).toBe("dropper.doc");
    expect(payloadDisplayName("https://x.example/a%20b.docx?x=1", "macro")).toBe("a_b.docx");
    expect(payloadDisplayName("https://x.example/", "steg")).toBe("payload.png");
  });

  it("renames a temp file when its extension is incompatible with the analyzer", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "secflow-payload-name-"));
    tempDirs.push(tempDir);
    const original = path.join(tempDir, "download.exe");
    await writeFile(original, "payload");

    const renamed = await ensureAnalyzerFileExtension(original, "macro");

    expect(renamed).toBe(`${original}.doc`);
    expect(path.extname(renamed)).toBe(".doc");
    await expect(access(original)).rejects.toThrow();
    expect(await readFile(renamed, "utf8")).toBe("payload");
  });
});
