import { END, START, StateGraph } from "@langchain/langgraph";

import { classifyInput } from "../classifier/index.js";
import type { AnalyzerName } from "../config.js";
import type { Logger } from "../logger.js";
import type { ModelClient } from "../model/types.js";
import type { PassCount, ResolvedInput } from "../pipeline/types.js";
import { analyzerToolResultSchema } from "../analyzers/schema.js";
import {
  availableToolNames,
  buildAvailableActions,
  toolsForTarget,
  type AvailableAction,
} from "./availability.js";
import { buildArtifactTargets } from "./artifacts.js";
import { DECISION_SYSTEM_PROMPT, buildDecisionPrompt } from "../prompts/decision.js";
import { decisionSchemaFor, validateDecision } from "./decision.js";
import { makeErrorId, makeToolRecordId } from "./ids.js";
import type { RawOutputStore } from "./rawOutputStore.js";
import {
  AnalysisStateAnnotation,
  analysisStateSchema,
  emptyCounters,
  emptyReportState,
  type AnalysisError,
  type AnalysisGraphState,
  type AnalysisState,
  type Termination,
  type TerminationReason,
  type ToolHistoryEntry,
} from "./state.js";
import type { AnalysisToolName } from "./schema/tools.js";
import type { ToolRegistry } from "./tools.js";

const ANALYZER_TOOL: Record<AnalyzerName, AnalysisToolName> = {
  malware: "analyze_malware",
  steg: "analyze_steg",
  recon: "analyze_recon",
  web: "analyze_web",
  macro: "analyze_macro",
};

export interface AnalysisGraphOptions {
  model: ModelClient;
  tools: ToolRegistry;
  runId: string;
  maxPasses: PassCount;
  maxCycles: number;
  maxToolCalls: number;
  rawOutputStore: RawOutputStore;
  logger?: Logger;
  signal?: AbortSignal;
}

export interface AnalysisLoopOptions extends AnalysisGraphOptions {
  input: ResolvedInput;
}

export type AnalysisLoopStatus = "completed" | "stopped" | "failed";

export interface AnalysisLoopResult {
  status: AnalysisLoopStatus;
  state: AnalysisState;
}

function terminate(reason: TerminationReason, pass: number, detail: string): Termination {
  return {
    reason,
    pass,
    detail,
    at: new Date().toISOString(),
  };
}

function errorEntry(
  state: AnalysisGraphState,
  stage: AnalysisError["stage"],
  code: string,
  message: string,
  recoverable: boolean,
): AnalysisError {
  return {
    id: makeErrorId(stage, `${message}:${state.errors.length}`, state.errors.length),
    stage,
    code,
    message: message.slice(0, 4_000),
    recoverable,
    at: new Date().toISOString(),
  };
}

function historyEntry(input: {
  state: AnalysisGraphState;
  action: { tool: AnalysisToolName; targetId: string; reasoning: string };
  pass: number;
  status: ToolHistoryEntry["status"];
  startedAt: string;
  durationMs: number;
  findingCount: number;
  riskScore: number;
  summary: string;
  rawOutputRef?: string;
  error?: string;
}): ToolHistoryEntry {
  return {
    id: makeToolRecordId(input.action.tool, input.action.targetId, input.state.toolHistory.length),
    pass: input.pass,
    tool: input.action.tool,
    targetId: input.action.targetId,
    status: input.status,
    startedAt: input.startedAt,
    durationMs: input.durationMs,
    findingCount: input.findingCount,
    riskScore: input.riskScore,
    summary: input.summary.slice(0, 4_000),
    reasoning: input.action.reasoning,
    ...(input.rawOutputRef ? { rawOutputRef: input.rawOutputRef } : {}),
    ...(input.error ? { error: input.error.slice(0, 4_000) } : {}),
  };
}

function statusFromTermination(termination: Termination | null): AnalysisLoopStatus {
  if (!termination) {
    return "completed";
  }
  if (termination.reason === "fatal_error" || termination.reason === "unsupported_input") {
    return "failed";
  }
  if (termination.reason === "model_finished" || termination.reason === "no_artifacts") {
    return "completed";
  }
  return "stopped";
}

function deterministicAction(
  state: AnalysisGraphState,
  available: readonly AvailableAction[],
): AvailableAction | undefined {
  if (
    state.counters.passes !== 0 ||
    !state.classification.deterministic ||
    !state.classification.analyzer
  ) {
    return undefined;
  }
  const tool = ANALYZER_TOOL[state.classification.analyzer];
  return available.find((action) => action.tool === tool && action.targetId === state.target.id);
}

export function buildAnalysisGraph(options: AnalysisGraphOptions) {
  const {
    model,
    tools,
    runId,
    maxPasses,
    maxCycles,
    maxToolCalls,
    rawOutputStore,
    logger,
    signal,
  } = options;

  const toolDescriptions: Record<string, string> = {};
  for (const name of tools.names()) {
    const tool = tools.get(name);
    if (tool) {
      toolDescriptions[name] = tool.description;
    }
  }

  async function decideNode(state: AnalysisGraphState) {
    if (state.termination) {
      return {};
    }

    if (state.counters.passes >= maxPasses) {
      return {
        termination: terminate(
          "max_passes",
          state.counters.passes,
          `Reached max passes (${maxPasses}).`,
        ),
      };
    }
    if (state.counters.toolCalls >= maxToolCalls) {
      return {
        termination: terminate(
          "max_tool_calls",
          state.counters.passes,
          `Reached tool-call budget (${maxToolCalls}).`,
        ),
      };
    }
    if (state.counters.cycles >= maxCycles) {
      return {
        termination: terminate(
          "max_cycles",
          state.counters.passes,
          `Reached model cycle budget (${maxCycles}).`,
        ),
      };
    }

    const available = buildAvailableActions({
      targets: state.targets,
      classification: state.classification,
      primaryTargetId: state.target.id,
      registeredTools: tools.names(),
      history: state.toolHistory,
    });

    if (available.length === 0) {
      const noActionYet = state.counters.passes === 0 && state.toolHistory.length === 0;
      const reason: TerminationReason = noActionYet ? "unsupported_input" : "no_artifacts";
      return {
        termination: terminate(
          reason,
          state.counters.passes,
          noActionYet
            ? `No analyzer tool can handle input type "${state.inputType}" (${state.classification.mimeType}).`
            : "No new action remains: every permitted tool/target pair has been attempted.",
        ),
      };
    }

    const first = deterministicAction(state, available);
    if (first) {
      const action = {
        tool: first.tool,
        targetId: first.targetId,
        reasoning: `Deterministic classifier selected ${first.tool} for ${state.inputType} input.`,
      };
      logger?.info(
        { runId, pass: state.counters.passes + 1, tool: action.tool, targetId: action.targetId },
        "deterministic first analyzer",
      );
      return { pendingAction: action };
    }

    const toolNames = availableToolNames(available);
    const prompt = buildDecisionPrompt({
      state,
      available,
      toolDescriptions,
      maxPasses,
      maxCycles,
      maxToolCalls,
    });

    let raw: unknown;
    try {
      raw = await model.generateObject({
        system: DECISION_SYSTEM_PROMPT,
        prompt,
        schema: decisionSchemaFor(toolNames),
        temperature: 0,
        maxOutputTokens: 500,
        ...(signal ? { abortSignal: signal } : {}),
      });
    } catch (error) {
      if (signal?.aborted) {
        throw error;
      }
      const message = error instanceof Error ? error.message : String(error);
      logger?.error({ runId, error: message }, "model decision failed");
      return {
        errors: [
          errorEntry(
            state,
            "model",
            "model_decision_failed",
            `Model decision failed: ${message}`,
            false,
          ),
        ],
        termination: terminate(
          "fatal_error",
          state.counters.passes,
          `Model decision failed: ${message}`,
        ),
        counters: { ...state.counters, cycles: state.counters.cycles + 1 },
        pendingAction: null,
      };
    }

    const validation = validateDecision(raw, {
      available,
      history: state.toolHistory,
    });
    const counters = { ...state.counters, cycles: state.counters.cycles + 1 };

    if (!validation.ok) {
      const message = `Rejected model decision: ${validation.error}`;
      logger?.warn({ runId, error: validation.error }, "rejected model decision");
      return {
        errors: [
          errorEntry(
            state,
            "validation",
            validation.kind === "duplicate" ? "duplicate_action" : "invalid_action",
            message,
            false,
          ),
        ],
        termination: terminate(
          validation.kind === "duplicate" ? "duplicate_analysis" : "fatal_error",
          state.counters.passes,
          message,
        ),
        counters,
        pendingAction: null,
      };
    }

    if (validation.action === null) {
      logger?.info(
        { runId, passes: state.counters.passes, reasoning: validation.reasoning },
        "model finished analysis",
      );
      return {
        termination: terminate("model_finished", state.counters.passes, validation.reasoning),
        counters,
        pendingAction: null,
      };
    }

    logger?.info(
      {
        runId,
        pass: state.counters.passes + 1,
        tool: validation.action.tool,
        targetId: validation.action.targetId,
        reasoning: validation.action.reasoning,
      },
      "model selected next analyzer",
    );
    return { pendingAction: validation.action, counters };
  }

  async function actNode(state: AnalysisGraphState) {
    const action = state.pendingAction;
    if (!action) {
      return {};
    }

    const target = state.targets.find((candidate) => candidate.id === action.targetId);
    if (!target) {
      return {
        errors: [
          errorEntry(
            state,
            "validation",
            "unknown_target",
            `Action referenced unknown target ${action.targetId}.`,
            false,
          ),
        ],
        termination: terminate(
          "fatal_error",
          state.counters.passes,
          "Action referenced an unknown target.",
        ),
        pendingAction: null,
      };
    }

    if (!toolsForTarget(target, state.classification, state.target.id).includes(action.tool)) {
      return {
        errors: [
          errorEntry(
            state,
            "validation",
            "tool_target_mismatch",
            `${action.tool} cannot analyze ${target.kind} target ${target.id}.`,
            false,
          ),
        ],
        termination: terminate(
          "fatal_error",
          state.counters.passes,
          "Selected tool does not accept the selected target kind.",
        ),
        pendingAction: null,
      };
    }

    const duplicate = state.toolHistory.some(
      (entry) => entry.tool === action.tool && entry.targetId === action.targetId,
    );
    if (duplicate) {
      return {
        termination: terminate(
          "duplicate_analysis",
          state.counters.passes,
          `${action.tool} already ran for target ${action.targetId}.`,
        ),
        pendingAction: null,
      };
    }

    const pass = state.counters.passes + 1;
    const startedAt = new Date().toISOString();
    const startedMs = Date.now();
    const targets = new Map(state.targets.map((candidate) => [candidate.id, candidate]));

    const result = await tools.execute(
      action.tool,
      { targetId: action.targetId },
      {
        runId,
        pass,
        targets,
        rawOutputStore,
        ...(signal ? { signal } : {}),
        ...(logger ? { logger } : {}),
      },
    );
    const durationMs = Date.now() - startedMs;

    if (!result.ok) {
      const message = result.error;
      logger?.error({ runId, tool: action.tool, error: message }, "analyzer tool failed");
      return {
        toolHistory: [
          historyEntry({
            state,
            action,
            pass,
            status: "failed",
            startedAt,
            durationMs,
            findingCount: 0,
            riskScore: 0,
            summary: `Tool failed: ${message}`,
            error: message,
          }),
        ],
        errors: [errorEntry(state, "tool", `${result.kind}_failure`, message, true)],
        counters: { ...state.counters, toolCalls: state.counters.toolCalls + 1 },
        pendingAction: null,
      };
    }

    const parsed = analyzerToolResultSchema.safeParse(result.output);
    if (!parsed.success) {
      const message = `Analyzer tool returned an invalid result: ${parsed.error.message}`;
      return {
        toolHistory: [
          historyEntry({
            state,
            action,
            pass,
            status: "failed",
            startedAt,
            durationMs,
            findingCount: 0,
            riskScore: 0,
            summary: message,
            error: message,
          }),
        ],
        errors: [errorEntry(state, "validation", "invalid_tool_output", message, false)],
        termination: terminate("fatal_error", state.counters.passes, message),
        counters: { ...state.counters, toolCalls: state.counters.toolCalls + 1 },
        pendingAction: null,
      };
    }

    const { secFlow, modelOutput } = parsed.data;
    const artifacts = buildArtifactTargets(secFlow, state.targets, state.indicators);
    const passes = state.counters.passes + 1;

    const history = historyEntry({
      state,
      action,
      pass,
      status: "succeeded",
      startedAt,
      durationMs,
      findingCount: secFlow.findings.length,
      riskScore: secFlow.risk_score,
      summary: modelOutput.summary,
      rawOutputRef: modelOutput.rawOutputRef.id,
    });

    const termination =
      passes >= maxPasses
        ? terminate("max_passes", passes, `Reached max passes (${maxPasses}).`)
        : null;

    logger?.info(
      {
        runId,
        pass,
        tool: action.tool,
        targetId: action.targetId,
        riskScore: secFlow.risk_score,
        findingCount: secFlow.findings.length,
        newTargets: artifacts.targets.length,
        durationMs,
      },
      "analyzer pass complete",
    );

    return {
      findings: [secFlow],
      targets: artifacts.targets,
      indicators: artifacts.indicators,
      toolHistory: [history],
      counters: {
        ...state.counters,
        passes,
        toolCalls: state.counters.toolCalls + 1,
      },
      termination,
      pendingAction: null,
    };
  }

  function afterDecide(state: AnalysisGraphState): "act" | typeof END {
    if (state.termination || !state.pendingAction) {
      return END;
    }
    return "act";
  }

  return new StateGraph(AnalysisStateAnnotation)
    .addNode("decide", decideNode)
    .addNode("act", actNode)
    .addEdge(START, "decide")
    .addConditionalEdges("decide", afterDecide, ["act", END])
    .addEdge("act", "decide")
    .compile();
}

function initialState(input: {
  classified: Awaited<ReturnType<typeof classifyInput>>;
  source: ResolvedInput;
  runId: string;
  maxPasses: PassCount;
  maxCycles: number;
  maxToolCalls: number;
  modelId: string;
}): AnalysisGraphState {
  const { classified, source } = input;
  return {
    runId: input.runId,
    source: {
      kind: source.kind,
      displayName: source.displayName,
      ...(source.originalName ? { originalName: source.originalName } : {}),
      mimeType: source.mimeType ?? classified.classification.mimeType,
      ...(source.sizeBytes !== undefined ? { sizeBytes: source.sizeBytes } : {}),
    },
    target: classified.target,
    targets: [classified.target],
    classification: classified.classification,
    inputType: classified.inputType,
    context: {
      runId: input.runId,
      startedAt: new Date().toISOString(),
      maxPasses: input.maxPasses,
      maxCycles: input.maxCycles,
      maxToolCalls: input.maxToolCalls,
      modelId: input.modelId,
    },
    findings: [],
    toolHistory: [],
    errors: [],
    indicators: [],
    rules: { yara: [], sigma: [] },
    report: emptyReportState(),
    termination: null,
    pendingAction: null,
    counters: emptyCounters(),
  };
}

/**
 * Run one analysis loop: deterministic first pass (when a rule matches), then
 * model-selected actions until finish or a budget/termination policy fires.
 */
export async function runAnalysisLoop(options: AnalysisLoopOptions): Promise<AnalysisLoopResult> {
  const classified = await classifyInput(options.input);
  const state = initialState({
    classified,
    source: options.input,
    runId: options.runId,
    maxPasses: options.maxPasses,
    maxCycles: options.maxCycles,
    maxToolCalls: options.maxToolCalls,
    modelId: options.model.modelId,
  });
  analysisStateSchema.parse(state);

  const graph = buildAnalysisGraph(options);
  const result = await graph.invoke(state, {
    recursionLimit: Math.max(10, options.maxCycles * 2 + options.maxPasses * 2 + 4),
    ...(options.signal ? { signal: options.signal } : {}),
  });

  const validated = analysisStateSchema.parse(result);
  return {
    status: statusFromTermination(validated.termination),
    state: validated,
  };
}
