import type { Logger } from "../../logger.js";
import { adaptWeb } from "../adapters/web.js";
import { requestJson, urlWithQuery } from "../http.js";
import { asRecord } from "../parse.js";
import type { AdaptedAnalyzerResult } from "../types.js";

interface WebRoute {
  key: string;
  path: string;
  timeoutMs: number;
}

/** Route order and per-route timeouts mirror the Python caller. */
const WEB_ROUTES: readonly WebRoute[] = [
  { key: "status", path: "status", timeoutMs: 15_000 },
  { key: "security_headers", path: "security-headers", timeoutMs: 20_000 },
  { key: "tls", path: "tls", timeoutMs: 20_000 },
  { key: "ssl", path: "ssl", timeoutMs: 20_000 },
  { key: "hsts", path: "hsts", timeoutMs: 15_000 },
  { key: "firewall", path: "firewall", timeoutMs: 20_000 },
  { key: "redirects", path: "redirects", timeoutMs: 20_000 },
  { key: "headers", path: "headers", timeoutMs: 15_000 },
  { key: "redirect_chain", path: "redirect-chain", timeoutMs: 30_000 },
  { key: "malware_check", path: "malware-check", timeoutMs: 30_000 },
  { key: "url_parse", path: "url-parse", timeoutMs: 10_000 },
  { key: "dns", path: "dns", timeoutMs: 15_000 },
];

export interface WebClientOptions {
  baseUrl: string;
  /** When set, replaces every per-route timeout (env override). */
  timeoutOverrideMs?: number;
  maxRetries?: number;
  maxResponseBytes?: number;
  logger?: Logger;
}

export class WebAnalyzerClient {
  private readonly baseUrl: string;
  private readonly timeoutOverrideMs: number | undefined;
  private readonly maxRetries: number;
  private readonly maxResponseBytes: number | undefined;
  private readonly logger: Logger | undefined;

  constructor(options: WebClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.timeoutOverrideMs = options.timeoutOverrideMs;
    this.maxRetries = options.maxRetries ?? 1;
    this.maxResponseBytes = options.maxResponseBytes;
    this.logger = options.logger;
  }

  async analyze(
    url: string,
    displayName: string,
    signal?: AbortSignal,
  ): Promise<AdaptedAnalyzerResult> {
    const aggregated: Record<string, unknown> = {};

    for (const route of WEB_ROUTES) {
      if (signal?.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error("web analysis aborted");
      }

      try {
        const response = await requestJson(urlWithQuery(this.baseUrl, route.path, { url }), {
          label: `web-analyzer ${route.key}`,
          timeoutMs: this.timeoutOverrideMs ?? route.timeoutMs,
          maxRetries: this.maxRetries,
          ...(this.maxResponseBytes !== undefined
            ? { maxResponseBytes: this.maxResponseBytes }
            : {}),
          ...(signal ? { signal } : {}),
          ...(this.logger ? { logger: this.logger } : {}),
        });
        aggregated[route.key] = asRecord(response);
      } catch (error) {
        this.logger?.warn({ error: String(error), route: route.key }, "web-analyzer route skipped");
      }
    }

    return adaptWeb(aggregated, displayName);
  }
}
