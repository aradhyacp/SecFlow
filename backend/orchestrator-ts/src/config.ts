import path from "node:path";

import { z } from "zod";

export const ANALYZER_NAMES = ["malware", "steg", "recon", "web", "macro"] as const;
export type AnalyzerName = (typeof ANALYZER_NAMES)[number];

const booleanString = z
  .enum(["true", "false", "1", "0"])
  .transform((value) => value === "true" || value === "1");

const analyzerBaseUrl = z
  .string()
  .url()
  .refine((value) => {
    try {
      const parsed = new URL(value);
      return (
        (parsed.protocol === "http:" || parsed.protocol === "https:") &&
        parsed.username.length === 0 &&
        parsed.password.length === 0
      );
    } catch {
      return false;
    }
  }, "must be an HTTP(S) URL without embedded credentials");

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65_535).default(5000),
  HOST: z.string().min(1).default("0.0.0.0"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),

  REPORTS_DIR: z.string().min(1).default("./reports"),
  MAX_UPLOAD_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .default(50 * 1024 * 1024),

  OPENROUTER_API_KEY: z.string().trim().min(1).optional(),
  OPENROUTER_MODEL: z.string().trim().min(1).default("nvidia/nemotron-3-ultra-550b-a55b:free"),
  MODEL_TEMPERATURE: z.coerce.number().min(0).max(2).default(0.1),
  MODEL_MAX_TOKENS: z.coerce.number().int().positive().max(32_000).default(2048),
  MODEL_TIMEOUT_MS: z.coerce.number().int().positive().default(60_000),
  MODEL_MAX_RETRIES: z.coerce.number().int().min(0).max(10).default(2),
  /** Model decisions per run. Must leave room for max passes plus a finish call. */
  MODEL_MAX_CYCLES: z.coerce.number().int().min(1).max(20).default(12),
  MODEL_MAX_TOOL_CALLS: z.coerce.number().int().min(1).max(50).default(20),

  ANALYZER_TIMEOUT_MS: z.coerce.number().int().positive().default(60_000),
  ANALYZER_MAX_RETRIES: z.coerce.number().int().min(0).max(5).default(1),
  /** Hard cap on an analyzer response body; prevents decompiler dumps from exhausting memory. */
  ANALYZER_MAX_RESPONSE_BYTES: z.coerce
    .number()
    .int()
    .positive()
    .max(100 * 1024 * 1024)
    .default(25 * 1024 * 1024),
  TOTAL_ANALYSIS_TIMEOUT_MS: z.coerce.number().int().positive().default(600_000),

  ANALYZER_MALWARE_URL: analyzerBaseUrl.default(
    "http://malware-analyzer:5000/api/malware-analyzer",
  ),
  ANALYZER_STEG_URL: analyzerBaseUrl.default("http://steg-analyzer:5000/api/steg-analyzer"),
  ANALYZER_RECON_URL: analyzerBaseUrl.default("http://recon-analyzer:5000/api/Recon-Analyzer"),
  ANALYZER_WEB_URL: analyzerBaseUrl.default("http://web-analyzer:5000/api/web-analyzer"),
  ANALYZER_MACRO_URL: analyzerBaseUrl.default("http://macro-analyzer:5000/api/macro-analyzer"),

  ANALYZER_MALWARE_TIMEOUT_MS: z.coerce.number().int().positive().optional(),
  ANALYZER_STEG_TIMEOUT_MS: z.coerce.number().int().positive().optional(),
  ANALYZER_RECON_TIMEOUT_MS: z.coerce.number().int().positive().optional(),
  ANALYZER_WEB_TIMEOUT_MS: z.coerce.number().int().positive().optional(),
  ANALYZER_MACRO_TIMEOUT_MS: z.coerce.number().int().positive().optional(),

  /** Permit loopback/private targets. Off by default; tests and local demos enable it. */
  ALLOW_PRIVATE_TARGETS: booleanString.default(false),
  /** Lets the service boot without a model key (health works, readiness stays 503). */
  ALLOW_MISSING_OPENROUTER_KEY: booleanString.default(false),
});

export type RawEnv = Record<string, string | undefined>;

export interface AnalyzerEndpointConfig {
  baseUrl: string;
  timeoutMs: number;
  /** Set only when the per-analyzer timeout env var was provided. */
  timeoutOverrideMs?: number;
}

export interface AppConfig {
  env: "development" | "test" | "production";
  port: number;
  host: string;
  logLevel: string;
  reportsDir: string;
  maxUploadBytes: number;
  model: {
    apiKey: string | null;
    modelId: string;
    temperature: number;
    maxTokens: number;
    timeoutMs: number;
    maxRetries: number;
    maxCycles: number;
    maxToolCalls: number;
  };
  analyzers: Record<AnalyzerName, AnalyzerEndpointConfig>;
  analyzerTimeoutMs: number;
  analyzerMaxRetries: number;
  analyzerMaxResponseBytes: number;
  totalAnalysisTimeoutMs: number;
  allowPrivateTargets: boolean;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const ANALYZER_URL_ENV: Record<AnalyzerName, string> = {
  malware: "ANALYZER_MALWARE_URL",
  steg: "ANALYZER_STEG_URL",
  recon: "ANALYZER_RECON_URL",
  web: "ANALYZER_WEB_URL",
  macro: "ANALYZER_MACRO_URL",
};

const ANALYZER_TIMEOUT_ENV: Record<AnalyzerName, string> = {
  malware: "ANALYZER_MALWARE_TIMEOUT_MS",
  steg: "ANALYZER_STEG_TIMEOUT_MS",
  recon: "ANALYZER_RECON_TIMEOUT_MS",
  web: "ANALYZER_WEB_TIMEOUT_MS",
  macro: "ANALYZER_MACRO_TIMEOUT_MS",
};

/**
 * Parse and validate configuration. Throws ConfigError with a readable list of
 * problems so a misconfigured container fails fast at startup.
 */
export function loadConfig(env: RawEnv = process.env): AppConfig {
  const parsed = envSchema.safeParse(env);

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`)
      .join("; ");
    throw new ConfigError(`Invalid configuration: ${issues}`);
  }

  const raw = parsed.data;

  if (
    raw.NODE_ENV === "production" &&
    !raw.OPENROUTER_API_KEY &&
    !raw.ALLOW_MISSING_OPENROUTER_KEY
  ) {
    throw new ConfigError(
      "OPENROUTER_API_KEY is required in production (set ALLOW_MISSING_OPENROUTER_KEY=true only for dry runs)",
    );
  }

  const analyzers = {} as Record<AnalyzerName, AnalyzerEndpointConfig>;
  for (const name of ANALYZER_NAMES) {
    const url = raw[ANALYZER_URL_ENV[name] as keyof typeof raw] as string;
    const override = raw[ANALYZER_TIMEOUT_ENV[name] as keyof typeof raw] as number | undefined;
    analyzers[name] = {
      baseUrl: url.replace(/\/+$/, ""),
      timeoutMs: override ?? raw.ANALYZER_TIMEOUT_MS,
      ...(override !== undefined ? { timeoutOverrideMs: override } : {}),
    };
  }

  return {
    env: raw.NODE_ENV,
    port: raw.PORT,
    host: raw.HOST,
    logLevel: raw.LOG_LEVEL,
    reportsDir: path.resolve(raw.REPORTS_DIR),
    maxUploadBytes: raw.MAX_UPLOAD_BYTES,
    model: {
      apiKey: raw.OPENROUTER_API_KEY ?? null,
      modelId: raw.OPENROUTER_MODEL,
      temperature: raw.MODEL_TEMPERATURE,
      maxTokens: raw.MODEL_MAX_TOKENS,
      timeoutMs: raw.MODEL_TIMEOUT_MS,
      maxRetries: raw.MODEL_MAX_RETRIES,
      maxCycles: raw.MODEL_MAX_CYCLES,
      maxToolCalls: raw.MODEL_MAX_TOOL_CALLS,
    },
    analyzers,
    analyzerTimeoutMs: raw.ANALYZER_TIMEOUT_MS,
    analyzerMaxRetries: raw.ANALYZER_MAX_RETRIES,
    analyzerMaxResponseBytes: raw.ANALYZER_MAX_RESPONSE_BYTES,
    totalAnalysisTimeoutMs: raw.TOTAL_ANALYSIS_TIMEOUT_MS,
    allowPrivateTargets: raw.ALLOW_PRIVATE_TARGETS,
  };
}
