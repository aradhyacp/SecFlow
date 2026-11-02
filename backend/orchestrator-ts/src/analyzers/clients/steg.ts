import { setTimeout as sleep } from "node:timers/promises";

import type { Logger } from "../../logger.js";
import { adaptSteg } from "../adapters/steg.js";
import { buildFileForm, requestJson } from "../http.js";
import { asRecord, asString } from "../parse.js";
import type { AdaptedAnalyzerResult } from "../types.js";

export interface StegClientOptions {
  baseUrl: string;
  uploadTimeoutMs?: number;
  statusTimeoutMs?: number;
  resultTimeoutMs?: number;
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  maxRetries?: number;
  maxResponseBytes?: number;
  logger?: Logger;
}

export class StegAnalyzerClient {
  private readonly baseUrl: string;
  private readonly uploadTimeoutMs: number;
  private readonly statusTimeoutMs: number;
  private readonly resultTimeoutMs: number;
  private readonly pollIntervalMs: number;
  private readonly pollTimeoutMs: number;
  private readonly maxRetries: number;
  private readonly maxResponseBytes: number | undefined;
  private readonly logger: Logger | undefined;

  constructor(options: StegClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.uploadTimeoutMs = options.uploadTimeoutMs ?? 30_000;
    this.statusTimeoutMs = options.statusTimeoutMs ?? 10_000;
    this.resultTimeoutMs = options.resultTimeoutMs ?? 30_000;
    this.pollIntervalMs = options.pollIntervalMs ?? 3_000;
    this.pollTimeoutMs = options.pollTimeoutMs ?? 300_000;
    this.maxRetries = options.maxRetries ?? 0;
    this.maxResponseBytes = options.maxResponseBytes;
    this.logger = options.logger;
  }

  async analyze(filePath: string, signal?: AbortSignal): Promise<AdaptedAnalyzerResult> {
    const submissionHash = await this.upload(filePath, signal);
    if (!submissionHash) {
      return adaptSteg({});
    }

    const completed = await this.waitForCompletion(submissionHash, signal);
    if (!completed) {
      return adaptSteg({});
    }

    try {
      const result = await requestJson(`${this.baseUrl}/result/${submissionHash}`, {
        label: "steg-analyzer result",
        timeoutMs: this.resultTimeoutMs,
        maxRetries: this.maxRetries,
        ...(this.maxResponseBytes !== undefined ? { maxResponseBytes: this.maxResponseBytes } : {}),
        ...(signal ? { signal } : {}),
        ...(this.logger ? { logger: this.logger } : {}),
      });
      return adaptSteg(result);
    } catch (error) {
      this.logger?.error({ error: String(error) }, "steg result fetch failed");
      return adaptSteg({});
    }
  }

  private async upload(filePath: string, signal?: AbortSignal): Promise<string | null> {
    try {
      const form = await buildFileForm(filePath, "image");
      const response = await requestJson(`${this.baseUrl}/upload`, {
        label: "steg-analyzer upload",
        method: "POST",
        body: form,
        timeoutMs: this.uploadTimeoutMs,
        maxRetries: this.maxRetries,
        ...(this.maxResponseBytes !== undefined ? { maxResponseBytes: this.maxResponseBytes } : {}),
        ...(signal ? { signal } : {}),
        ...(this.logger ? { logger: this.logger } : {}),
      });
      const submissionHash = asString(asRecord(response).submission_hash);
      if (!submissionHash) {
        throw new Error("No submission_hash in upload response");
      }
      return submissionHash;
    } catch (error) {
      this.logger?.error({ error: String(error) }, "steg upload failed");
      return null;
    }
  }

  private async waitForCompletion(hash: string, signal?: AbortSignal): Promise<boolean> {
    const deadline = Date.now() + this.pollTimeoutMs;
    while (Date.now() < deadline) {
      if (signal?.aborted) {
        throw signal.reason instanceof Error ? signal.reason : new Error("steg polling aborted");
      }

      try {
        const response = await requestJson(`${this.baseUrl}/status/${hash}`, {
          label: "steg-analyzer status",
          timeoutMs: this.statusTimeoutMs,
          maxRetries: this.maxRetries,
          ...(this.maxResponseBytes !== undefined
            ? { maxResponseBytes: this.maxResponseBytes }
            : {}),
          ...(signal ? { signal } : {}),
          ...(this.logger ? { logger: this.logger } : {}),
        });
        const status = asString(asRecord(response).status);
        if (status === "completed") {
          return true;
        }
        if (status === "error") {
          this.logger?.error("steg analysis reported error status");
          return false;
        }
      } catch (error) {
        if (signal?.aborted) {
          throw error;
        }
        this.logger?.warn({ error: String(error) }, "steg status poll error");
      }

      await sleep(this.pollIntervalMs, undefined, signal ? { signal } : undefined);
    }

    this.logger?.error("steg polling timed out");
    return false;
  }
}
