import { z } from "zod";

import { formatIssues } from "./tools.js";
import { analysisToolNames, TARGET_ID_PATTERN, type AnalysisToolName } from "./schema/tools.js";
import type { AnalysisAction, ToolHistoryEntry } from "./state.js";
import type { AvailableAction } from "./availability.js";

export const FINISH_ACTION = "finish" as const;
export type DecisionActionName = AnalysisToolName | typeof FINISH_ACTION;

/**
 * Wire schema for one model decision. `action` is an enumerated choice, never
 * free-form JSON; `targetId` must resolve through the trusted target catalog.
 */
export const analysisDecisionSchema = z
  .object({
    action: z.enum([...analysisToolNames, FINISH_ACTION]),
    targetId: z.string().regex(TARGET_ID_PATTERN).optional(),
    reasoning: z.string().min(1).max(2_000),
  })
  .strict();
export type AnalysisDecision = z.infer<typeof analysisDecisionSchema>;

/** Narrow the enum to the tools that are actually available this cycle. */
export function decisionSchemaFor(tools: readonly AnalysisToolName[]) {
  const actions = [...tools, FINISH_ACTION] as unknown as [string, ...string[]];
  return z
    .object({
      action: z.enum(actions),
      targetId: z.string().regex(TARGET_ID_PATTERN).optional(),
      reasoning: z.string().min(1).max(2_000),
    })
    .strict();
}

export type DecisionValidation =
  | { ok: true; action: AnalysisAction | null; reasoning: string }
  | { ok: false; kind: "invalid" | "duplicate"; error: string };

/**
 * Validate a decision against the current action allowlist. The provider's
 * structured-output schema already restricts `action`, but the graph repeats
 * validation because model output is untrusted.
 */
export function validateDecision(
  raw: unknown,
  options: {
    available: readonly AvailableAction[];
    history: readonly ToolHistoryEntry[];
  },
): DecisionValidation {
  const parsed = analysisDecisionSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, kind: "invalid", error: formatIssues(parsed.error) };
  }

  const decision = parsed.data;
  if (decision.action === FINISH_ACTION) {
    if (decision.targetId !== undefined) {
      return {
        ok: false,
        kind: "invalid",
        error: "finish must not include a targetId",
      };
    }
    return { ok: true, action: null, reasoning: decision.reasoning };
  }

  if (!decision.targetId) {
    return {
      ok: false,
      kind: "invalid",
      error: `${decision.action} requires a targetId from the available action list`,
    };
  }

  const allowed = options.available.some(
    (action) => action.tool === decision.action && action.targetId === decision.targetId,
  );
  if (!allowed) {
    const duplicate = options.history.some(
      (entry) => entry.tool === decision.action && entry.targetId === decision.targetId,
    );
    return {
      ok: false,
      kind: duplicate ? "duplicate" : "invalid",
      error: duplicate
        ? `${decision.action} was already attempted for ${decision.targetId}`
        : `${decision.action} is not available for ${decision.targetId}`,
    };
  }

  return {
    ok: true,
    action: {
      tool: decision.action,
      targetId: decision.targetId,
      reasoning: decision.reasoning,
    },
    reasoning: decision.reasoning,
  };
}
