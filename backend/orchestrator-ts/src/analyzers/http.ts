import { readFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import type { Logger } from "../logger.js";

export class AnalyzerHttpError extends Error {
  readonly status: number | undefined;
  readonly retriable: boolean;
  readonly bodyPreview: string | undefined;

  constructor(
    message: string,
    options: { status?: number; retriable: boolean; bodyPreview?: string; cause?: unknown },
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "AnalyzerHttpError";
    this.status = options.status;
    this.retriable = options.retriable;
    this.bodyPreview = options.bodyPreview;
  }
}

export interface JsonRequestOptions {
  label: string;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: FormData | string;
  timeoutMs: number;
  maxRetries?: number;
  retryDelayMs?: number;
  signal?: AbortSignal;
  logger?: Logger;
}

function isRetriableStatus(status: number): boolean {
  return status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}

function isRetriableError(error: unknown): boolean {
  if (error instanceof AnalyzerHttpError) {
    return error.retriable;
  }
  if (isAbortError(error)) {
    return true;
  }
  // fetch throws TypeError for network-level failures.
  return error instanceof TypeError;
}

function preview(text: string, maxChars = 2_000): string {
  return text.length > maxChars ? `${text.slice(0, maxChars)}…` : text;
}

/**
 * Fetch JSON with a hard timeout and a bounded retry policy.
 *
 * Only transient failures (network errors, timeouts, 429/5xx) are retried.
 * Heavy analyzer POSTs should pass `maxRetries: 0`.
 */
export async function requestJson<T = unknown>(
  url: string,
  options: JsonRequestOptions,
): Promise<T> {
  const maxRetries = options.maxRetries ?? 0;
  const retryDelayMs = options.retryDelayMs ?? 500;
  const startedAt = Date.now();
  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const timeout = AbortSignal.timeout(options.timeoutMs);
    const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;

    try {
      const response = await fetch(url, {
        method: options.method ?? "GET",
        ...(options.headers ? { headers: options.headers } : {}),
        ...(options.body ? { body: options.body } : {}),
        signal,
      });

      const text = await response.text();
      if (!response.ok) {
        throw new AnalyzerHttpError(`${options.label} returned HTTP ${response.status}`, {
          status: response.status,
          retriable: isRetriableStatus(response.status),
          bodyPreview: preview(text),
        });
      }

      try {
        return JSON.parse(text) as T;
      } catch (error) {
        throw new AnalyzerHttpError(`${options.label} returned invalid JSON`, {
          status: response.status,
          retriable: false,
          bodyPreview: preview(text),
          cause: error,
        });
      }
    } catch (error) {
      lastError = error;
      const parentAborted = options.signal?.aborted === true;
      if (parentAborted || !isRetriableError(error) || attempt >= maxRetries) {
        throw error;
      }

      const delay = Math.min(retryDelayMs * 2 ** attempt, 5_000);
      options.logger?.warn(
        {
          label: options.label,
          attempt: attempt + 1,
          delayMs: delay,
          error: error instanceof Error ? error.message : String(error),
        },
        "analyzer request retry",
      );
      await sleep(delay, undefined, options.signal ? { signal: options.signal } : undefined);
    }
  }

  options.logger?.debug(
    { label: options.label, durationMs: Date.now() - startedAt },
    "analyzer request failed",
  );
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

export async function buildFileForm(filePath: string, field: string): Promise<FormData> {
  const contents = await readFile(filePath);
  const filename = path.basename(filePath) || "upload.bin";
  const form = new FormData();
  form.append(field, new Blob([contents]), filename);
  return form;
}

export function urlWithQuery(
  baseUrl: string,
  pathname: string,
  query: Record<string, string>,
): string {
  const url = new URL(`${baseUrl.replace(/\/+$/, "")}/${pathname.replace(/^\/+/, "")}`);
  for (const [key, value] of Object.entries(query)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}
