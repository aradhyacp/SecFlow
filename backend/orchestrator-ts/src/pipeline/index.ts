import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";

import type { AppConfig } from "../config.js";
import { ConfigError } from "../config.js";
import { finalizeAnalysis } from "../graph/finalize.js";
import { runAnalysisLoop } from "../graph/analysis.js";
import { InMemoryRawOutputStore, type RawOutputStore } from "../graph/rawOutputStore.js";
import { ToolRegistry } from "../graph/tools.js";
import { errorMessage, HttpError } from "../http/errors.js";
import type { Logger } from "../logger.js";
import { redactSensitive } from "../logger.js";
import { createModelClient, type ModelFactory } from "../model/provider.js";
import type { ModelClient } from "../model/types.js";
import { createRuleGenerationTools } from "../rules/tools.js";
import { createReportTool } from "../report/tools.js";
import { createAnalyzerToolRegistry } from "../analyzers/tools.js";
import {
  createNetworkGuard,
  SsrfBlockedError,
  type NetworkGuard,
} from "../security/networkGuard.js";
import type { AnalysisRequest, AnalysisResponse, AnalysisRunner, ResolvedInput } from "./types.js";

export interface RunnerDependencies {
  /** Inject a scripted model in tests; production constructs OpenRouter. */
  model?: ModelClient;
  /** Replace the five analyzer tools with deterministic fixtures. */
  analyzerRegistry?: ToolRegistry;
  /** `null` disables the optional report narrative. Defaults to the run model. */
  reportModel?: ModelClient | null;
  rawOutputStore?: RawOutputStore;
  guard?: NetworkGuard;
  modelFactory?: ModelFactory;
  now?: () => Date;
}

function normalizeRunId(value: string): string {
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= 200 ? trimmed : randomUUID();
}

async function hashInput(input: ResolvedInput): Promise<string> {
  const hash = createHash("sha256");
  if (input.kind === "target") {
    hash.update(input.value);
  } else {
    for await (const chunk of createReadStream(input.value)) {
      hash.update(chunk as Buffer);
    }
  }
  return hash.digest("hex").slice(0, 16);
}

function overallRisk(findings: AnalysisResponse["findingsSummary"]): number {
  return Math.round(Math.max(0, ...findings.map((finding) => finding.risk_score)) * 100) / 100;
}

function logError(error: unknown): { name: string; code?: string; message: string } {
  const name = error instanceof Error ? error.name : "Error";
  const code =
    typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
      ? error.code
      : undefined;
  const message = redactSensitive(errorMessage(error)).replace(/\s+/g, " ").slice(0, 2_000);
  return { name, ...(code ? { code } : {}), message };
}

export function createAnalysisRunner(
  config: AppConfig,
  logger: Logger,
  dependencies: RunnerDependencies = {},
): AnalysisRunner {
  let shared:
    | {
        model: ModelClient;
        guard: NetworkGuard;
      }
    | undefined;

  function buildShared(): {
    model: ModelClient;
    guard: NetworkGuard;
  } {
    if (shared) {
      return shared;
    }

    let model = dependencies.model;
    if (!model) {
      if (!config.model.apiKey) {
        throw new HttpError(
          503,
          "OPENROUTER_API_KEY is not configured — analysis cannot run until it is set",
        );
      }
      try {
        model = createModelClient(config, logger, dependencies.modelFactory);
      } catch (error) {
        if (error instanceof ConfigError) {
          throw new HttpError(503, error.message);
        }
        throw error;
      }
    }

    const guard =
      dependencies.guard ?? createNetworkGuard({ allowPrivateTargets: config.allowPrivateTargets });

    shared = { model, guard };
    return shared;
  }

  /**
   * Build run-scoped tools so every analyzer client, rule stage and report
   * stage logs through a logger with the run id already bound.
   */
  function registryForRun(
    model: ModelClient,
    guard: NetworkGuard,
    runLogger: Logger,
  ): ToolRegistry {
    const analyzerRegistry =
      dependencies.analyzerRegistry ?? createAnalyzerToolRegistry(config, runLogger, { guard });

    const reportModel =
      dependencies.reportModel === null ? undefined : (dependencies.reportModel ?? model);

    const reportTool = createReportTool({
      reportsDir: config.reportsDir,
      ...(reportModel ? { model: reportModel } : {}),
      logger: runLogger,
      ...(dependencies.now ? { now: dependencies.now } : {}),
    });

    return new ToolRegistry([
      ...analyzerRegistry.all(),
      ...createRuleGenerationTools({ model, logger: runLogger }),
      reportTool,
    ]);
  }

  return {
    async run(request: AnalysisRequest): Promise<AnalysisResponse> {
      const startedAt = Date.now();
      const runId = normalizeRunId(request.runId);
      const runLogger = request.logger.child({ runId });
      let jobId = "";

      try {
        const { model, guard } = buildShared();
        const registry = registryForRun(model, guard, runLogger);
        jobId = await hashInput(request.input);

        runLogger.info(
          {
            runId,
            jobId,
            event: "run_started",
            inputKind: request.input.kind,
            inputBytes: request.input.sizeBytes ?? Buffer.byteLength(request.input.value, "utf8"),
            maxPasses: request.maxPasses,
            model: model.modelId,
          },
          "analysis run started",
        );

        const loop = await runAnalysisLoop({
          input: request.input,
          model,
          tools: registry,
          runId,
          maxPasses: request.maxPasses,
          maxCycles: config.model.maxCycles,
          maxToolCalls: config.model.maxToolCalls,
          decisionMaxOutputTokens: config.model.maxTokens,
          rawOutputStore: dependencies.rawOutputStore ?? new InMemoryRawOutputStore(),
          guard,
          logger: runLogger,
          signal: request.signal,
        });

        runLogger.info(
          {
            runId,
            jobId,
            event: "analysis_loop_completed",
            status: loop.status,
            termination: loop.state.termination?.reason ?? null,
            passes: loop.state.findings.length,
            findings: loop.state.findings.reduce(
              (count, result) => count + result.findings.length,
              0,
            ),
            durationMs: Date.now() - startedAt,
          },
          "analysis loop completed",
        );

        if (request.signal.aborted) {
          throw new HttpError(504, "Analysis exceeded TOTAL_ANALYSIS_TIMEOUT_MS");
        }
        if (loop.state.findings.length === 0) {
          throw new HttpError(500, "Pipeline produced no findings");
        }

        const finalized = await finalizeAnalysis({
          state: loop.state,
          registry,
          jobId,
          logger: runLogger,
          signal: request.signal,
          ...(dependencies.now ? { now: dependencies.now } : {}),
        });

        if (request.signal.aborted) {
          throw new HttpError(504, "Analysis exceeded TOTAL_ANALYSIS_TIMEOUT_MS");
        }
        const jsonPath = finalized.report.jsonPath;
        const htmlPath = finalized.report.htmlPath;
        if (finalized.report.status !== "generated" || !jsonPath || !htmlPath) {
          throw new HttpError(
            500,
            `Report generation ${finalized.report.status}: ${
              finalized.report.error ?? "report paths were not produced"
            }`,
          );
        }

        const riskScore = overallRisk(finalized.findings);
        const response: AnalysisResponse = {
          jobId,
          passesCompleted: finalized.findings.length,
          overallRiskScore: riskScore,
          findingsSummary: finalized.findings,
          reportPaths: { json: jsonPath, html: htmlPath },
          reportUrls: {
            json: `/api/report/${jobId}/json`,
            html: `/api/report/${jobId}/html`,
          },
        };

        runLogger.info(
          {
            runId,
            jobId,
            event: "run_completed",
            passesCompleted: response.passesCompleted,
            overallRiskScore: response.overallRiskScore,
            reportStatus: finalized.report.status,
            durationMs: Date.now() - startedAt,
          },
          "analysis run completed",
        );

        return response;
      } catch (error) {
        const normalized = (() => {
          if (error instanceof SsrfBlockedError || error instanceof HttpError) {
            return error;
          }
          if (request.signal.aborted) {
            return new HttpError(504, "Analysis exceeded TOTAL_ANALYSIS_TIMEOUT_MS");
          }
          if (
            error instanceof Error &&
            (error.name === "AbortError" || error.name === "TimeoutError")
          ) {
            return new HttpError(504, "Analysis exceeded TOTAL_ANALYSIS_TIMEOUT_MS");
          }
          return error;
        })();

        runLogger.error(
          {
            runId,
            ...(jobId ? { jobId } : {}),
            event: "run_failed",
            durationMs: Date.now() - startedAt,
            error: logError(normalized),
          },
          "analysis run failed",
        );
        throw normalized;
      }
    },
  };
}
