import { randomUUID } from "node:crypto";
import { mkdtemp, open, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import type { Logger } from "../logger.js";
import type { NetworkGuard } from "../security/networkGuard.js";

export const DEFAULT_PAYLOAD_MAX_BYTES = 50 * 1024 * 1024;
export const DEFAULT_PAYLOAD_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_REDIRECTS = 5;

export class PayloadDownloadError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PayloadDownloadError";
    this.code = code;
  }
}

export interface DownloadedPayload {
  /** Final URL after redirects. */
  url: string;
  path: string;
  contentType: string;
  sizeBytes: number;
}

export interface DownloadPayloadOptions {
  guard: NetworkGuard;
  signal?: AbortSignal;
}

/**
 * Downloads analyzer-discovered payloads to an isolated per-run directory.
 * Every redirect hop is re-checked by the SSRF guard before it is fetched.
 */
export interface PayloadDownloader {
  download(url: string, options: DownloadPayloadOptions): Promise<DownloadedPayload>;
  cleanup(): Promise<void>;
}

export interface HttpPayloadDownloaderOptions {
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  logger?: Logger;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SAFE_EXTENSION = /^\.[a-z0-9]{1,10}$/i;

function extensionForUrl(url: URL): string {
  const extension = path.extname(url.pathname).toLowerCase();
  return SAFE_EXTENSION.test(extension) ? extension : ".bin";
}

function contentTypeOf(response: Response): string {
  const raw = response.headers.get("content-type") ?? "application/octet-stream";
  return raw.split(";")[0]?.trim().toLowerCase() || "application/octet-stream";
}

function timeoutSignal(timeoutMs: number, outer: AbortSignal | undefined): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return outer ? AbortSignal.any([outer, timeout]) : timeout;
}

export class HttpPayloadDownloader implements PayloadDownloader {
  private readonly maxBytes: number;
  private readonly timeoutMs: number;
  private readonly maxRedirects: number;
  private readonly logger: Logger | undefined;
  private directory: Promise<string> | undefined;

  constructor(options: HttpPayloadDownloaderOptions = {}) {
    this.maxBytes = options.maxBytes ?? DEFAULT_PAYLOAD_MAX_BYTES;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_PAYLOAD_TIMEOUT_MS;
    this.maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.logger = options.logger;
  }

  private ensureDirectory(): Promise<string> {
    this.directory ??= mkdtemp(path.join(tmpdir(), "secflow-payload-"));
    return this.directory;
  }

  private async writeBody(
    response: Response,
    filePath: string,
    maxBytes: number,
  ): Promise<number> {
    if (!response.body) {
      throw new PayloadDownloadError("empty_body", "Payload response had no body");
    }

    const handle = await open(filePath, "wx");
    let size = 0;
    try {
      const reader = response.body.getReader();
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) {
          break;
        }
        const value = chunk.value as Uint8Array;
        size += value.byteLength;
        if (size > maxBytes) {
          await reader.cancel().catch(() => undefined);
          throw new PayloadDownloadError(
            "payload_too_large",
            `Payload exceeded ${maxBytes} bytes`,
          );
        }
        await handle.write(value);
      }
    } catch (error) {
      await handle.close().catch(() => undefined);
      await unlink(filePath).catch(() => undefined);
      throw error;
    }
    await handle.close();
    return size;
  }

  async download(url: string, options: DownloadPayloadOptions): Promise<DownloadedPayload> {
    let current: URL;
    try {
      current = new URL(url);
    } catch {
      throw new PayloadDownloadError("invalid_url", "Payload URL is not a valid URL");
    }

    for (let redirects = 0; redirects <= this.maxRedirects; redirects += 1) {
      await options.guard.assertTargetAllowed({
        kind: "url",
        value: current.toString(),
        displayName: current.toString(),
      });

      const response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        headers: { accept: "*/*", "user-agent": "SecFlow/0.1" },
        signal: timeoutSignal(this.timeoutMs, options.signal),
      });

      if (REDIRECT_STATUSES.has(response.status)) {
        const location = response.headers.get("location");
        await response.body?.cancel().catch(() => undefined);
        if (!location) {
          throw new PayloadDownloadError(
            "invalid_redirect",
            `Payload redirect from ${current.hostname} had no Location header`,
          );
        }
        try {
          current = new URL(location, current);
        } catch {
          throw new PayloadDownloadError(
            "invalid_redirect",
            `Payload redirect from ${current.hostname} was not a valid URL`,
          );
        }
        continue;
      }

      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        throw new PayloadDownloadError(
          "http_error",
          `Payload download returned HTTP ${response.status}`,
        );
      }

      const contentType = contentTypeOf(response);
      const declaredLength = response.headers.get("content-length");
      if (declaredLength !== null && Number(declaredLength) > this.maxBytes) {
        await response.body?.cancel().catch(() => undefined);
        throw new PayloadDownloadError(
          "payload_too_large",
          `Payload Content-Length exceeds ${this.maxBytes} bytes`,
        );
      }

      const directory = await this.ensureDirectory();
      const filePath = path.join(directory, `${randomUUID()}${extensionForUrl(current)}`);
      const sizeBytes = await this.writeBody(response, filePath, this.maxBytes);

      this.logger?.info(
        {
          event: "payload_download",
          host: current.hostname,
          contentType,
          sizeBytes,
          extension: path.extname(filePath),
        },
        "payload downloaded",
      );

      return { url: current.toString(), path: filePath, contentType, sizeBytes };
    }

    throw new PayloadDownloadError(
      "too_many_redirects",
      `Payload download exceeded ${this.maxRedirects} redirects`,
    );
  }

  async cleanup(): Promise<void> {
    const directory = this.directory;
    this.directory = undefined;
    if (directory) {
      const resolved = await directory.catch(() => undefined);
      if (resolved) {
        await rm(resolved, { recursive: true, force: true }).catch(() => undefined);
      }
    }
  }
}
