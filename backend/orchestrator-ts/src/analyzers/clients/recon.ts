import type { Logger } from "../../logger.js";
import { adaptRecon } from "../adapters/recon.js";
import { requestJson } from "../http.js";
import type { AdaptedAnalyzerResult } from "../types.js";

const IP_REGEX =
  /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const DOMAIN_REGEX = /^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/;

export function isIpOrDomain(value: string): boolean {
  return IP_REGEX.test(value) || DOMAIN_REGEX.test(value);
}

export interface ReconClientOptions {
  baseUrl: string;
  timeoutMs?: number;
  maxRetries?: number;
  maxResponseBytes?: number;
  logger?: Logger;
}

export class ReconAnalyzerClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly maxResponseBytes: number | undefined;
  private readonly logger: Logger | undefined;

  constructor(options: ReconClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.maxRetries = options.maxRetries ?? 1;
    this.maxResponseBytes = options.maxResponseBytes;
    this.logger = options.logger;
  }

  async analyze(
    query: string,
    displayName: string,
    signal?: AbortSignal,
  ): Promise<AdaptedAnalyzerResult> {
    const endpoint = isIpOrDomain(query) ? "scan" : "footprint";
    try {
      const response = await requestJson(`${this.baseUrl}/${endpoint}`, {
        label: `recon-analyzer ${endpoint}`,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query }),
        timeoutMs: this.timeoutMs,
        maxRetries: this.maxRetries,
        ...(this.maxResponseBytes !== undefined ? { maxResponseBytes: this.maxResponseBytes } : {}),
        ...(signal ? { signal } : {}),
        ...(this.logger ? { logger: this.logger } : {}),
      });
      return adaptRecon(response, displayName);
    } catch (error) {
      this.logger?.error({ error: String(error), endpoint }, "recon call failed");
      return adaptRecon({}, displayName);
    }
  }
}
