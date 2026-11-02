import type { Logger } from "../../logger.js";
import { adaptMacro } from "../adapters/macro.js";
import { buildFileForm, requestJson } from "../http.js";
import type { AdaptedAnalyzerResult } from "../types.js";

export interface MacroClientOptions {
  baseUrl: string;
  timeoutMs?: number;
  maxRetries?: number;
  maxResponseBytes?: number;
  logger?: Logger;
}

export class MacroAnalyzerClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly maxResponseBytes: number | undefined;
  private readonly logger: Logger | undefined;

  constructor(options: MacroClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.maxRetries = options.maxRetries ?? 0;
    this.maxResponseBytes = options.maxResponseBytes;
    this.logger = options.logger;
  }

  async analyze(
    filePath: string,
    displayName: string,
    signal?: AbortSignal,
  ): Promise<AdaptedAnalyzerResult> {
    try {
      const form = await buildFileForm(filePath, "file");
      const response = await requestJson(`${this.baseUrl}/analyze`, {
        label: "macro-analyzer analyze",
        method: "POST",
        body: form,
        timeoutMs: this.timeoutMs,
        maxRetries: this.maxRetries,
        ...(this.maxResponseBytes !== undefined ? { maxResponseBytes: this.maxResponseBytes } : {}),
        ...(signal ? { signal } : {}),
        ...(this.logger ? { logger: this.logger } : {}),
      });
      return adaptMacro(response, displayName);
    } catch (error) {
      this.logger?.error({ error: String(error) }, "macro call failed");
      return adaptMacro(
        { success: false, error: `macro-analyzer call failed: ${String(error)}` },
        displayName,
      );
    }
  }
}
