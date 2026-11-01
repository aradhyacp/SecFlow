import pino, { type Logger } from "pino";

import type { AppConfig } from "./config.js";

const SECRET_REDACTION_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  "res.headers['set-cookie']",
  "apiKey",
  "*.apiKey",
  "*.api_key",
  "OPENROUTER_API_KEY",
  "*.OPENROUTER_API_KEY",
];

/**
 * Structured JSON logger. Secrets are redacted by key name; callers must still
 * avoid logging raw sample bytes (see `redactSensitive`).
 */
export function createLogger(config: Pick<AppConfig, "logLevel" | "env">): Logger {
  return pino({
    level: config.env === "test" ? "silent" : config.logLevel,
    redact: { paths: SECRET_REDACTION_PATHS, censor: "[REDACTED]" },
    base: { service: "secflow-orchestrator" },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}

const API_KEY_PATTERNS = [
  /\b(sk-[A-Za-z0-9_-]{8,})/g,
  /\b(sk-or-[A-Za-z0-9_-]{8,})/g,
  /\b([A-Fa-f0-9]{32,})\b/g,
];

/** Strip anything that looks like a credential before it reaches a log line. */
export function redactSensitive(value: string): string {
  let result = value;
  for (const pattern of API_KEY_PATTERNS) {
    result = result.replace(pattern, "[REDACTED]");
  }
  return result;
}

export type { Logger };
