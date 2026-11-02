import type { LanguageModel } from "ai";

import type {
  ModelClient,
  ModelDecision,
  ModelDecisionRequest,
  StructuredObjectRequest,
} from "../../src/model/types.js";
import type { AnalysisDecision } from "../../src/graph/decision.js";

export function finish(reasoning = "No further analysis adds value."): AnalysisDecision {
  return { action: "finish", targetId: null, reasoning };
}

export function choose(
  action: AnalysisDecision["action"],
  targetId: string,
  reasoning = "Concrete evidence justifies this pass.",
): AnalysisDecision {
  return { action, targetId, reasoning };
}

/**
 * Deterministic stand-in for generateObject-based decisions. Set
 * `enforceSchema` to false when a test needs to exercise graph-side rejection
 * of a decision the provider schema would normally forbid.
 */
export class ScriptedDecisionModel implements ModelClient {
  readonly modelId = "scripted-decision-model";
  readonly model = {} as LanguageModel;
  readonly requests: Array<StructuredObjectRequest<unknown>> = [];
  private readonly decisions: AnalysisDecision[];

  constructor(
    decisions: AnalysisDecision[],
    private readonly enforceSchema = true,
  ) {
    this.decisions = [...decisions];
  }

  async decide(_request: ModelDecisionRequest): Promise<ModelDecision> {
    throw new Error("ScriptedDecisionModel only implements generateObject");
  }

  async generateObject<T>(request: StructuredObjectRequest<T>): Promise<T> {
    this.requests.push(request);
    const decision = this.decisions.shift();
    if (!decision) {
      throw new Error("Scripted decision model ran out of decisions");
    }
    if (this.enforceSchema) {
      return request.schema.parse(decision);
    }
    // Tests intentionally bypass provider-side validation on this path.
    return decision as T;
  }
}
