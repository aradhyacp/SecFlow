import type { Logger } from "../logger.js";
import type { ModelClient } from "../model/types.js";
import { makeRuleId } from "../graph/ids.js";
import type { RuleArtifact, RuleGenerationOutput, RuleKind } from "../graph/schema/rules.js";
import type { AnalysisState } from "../graph/state.js";
import { buildRuleEvidence, type RuleEvidence } from "./evidence.js";
import { sigmaGroundingErrors, yaraGroundingErrors } from "./grounding.js";
import {
  buildSigmaPrompt,
  buildYaraPrompt,
  SIGMA_SYSTEM_PROMPT,
  YARA_SYSTEM_PROMPT,
} from "../prompts/rules.js";
import {
  sigmaGenerationDraftSchema,
  yaraGenerationDraftSchema,
  type SigmaGenerationDraft,
  type YaraGenerationDraft,
} from "./schemas.js";
import { validateSigma } from "./sigmaValidator.js";
import { validateYara } from "./yaraValidator.js";

export interface RuleGenerationOptions {
  model: ModelClient;
  logger?: Logger;
  now?: () => Date;
  signal?: AbortSignal;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function resolveRefs(
  requested: readonly string[],
  evidence: RuleEvidence,
): { refs: string[]; errors: string[] } {
  const allowed = new Set(evidence.evidenceRefs);
  const refs = [...new Set(requested.filter((ref) => allowed.has(ref)))];
  const unknown = requested.filter((ref) => !allowed.has(ref));
  return {
    refs,
    errors: unknown.length > 0 ? [`Unknown evidence_ref(s): ${unknown.join(", ")}`] : [],
  };
}

function artifact(input: {
  kind: RuleKind;
  content: string;
  name?: string;
  description?: string;
  tags: string[];
  reasoning: string;
  status: RuleArtifact["status"];
  validationErrors: string[];
  evidenceRefs: string[];
  createdAt: string;
}): RuleArtifact {
  return {
    id: makeRuleId(input.kind, input.content),
    kind: input.kind,
    ...(input.name ? { name: input.name } : {}),
    ...(input.description ? { description: input.description } : {}),
    tags: input.tags,
    content: input.content,
    reasoning: input.reasoning,
    status: input.status,
    validationErrors: input.validationErrors.slice(0, 100),
    evidenceRefs: input.evidenceRefs,
    createdAt: input.createdAt,
  };
}

function overallStatus(rules: readonly RuleArtifact[]): "generated" | "invalid" | "skipped" {
  if (rules.length === 0) {
    return "skipped";
  }
  return rules.some((rule) => rule.status === "valid" || rule.status === "generated")
    ? "generated"
    : "invalid";
}

function dedupeRules(rules: readonly RuleArtifact[]): RuleArtifact[] {
  const byId = new Map<string, RuleArtifact>();
  for (const rule of rules) {
    byId.set(rule.id, rule);
  }
  return [...byId.values()];
}

export async function generateYaraRules(
  state: AnalysisState,
  options: RuleGenerationOptions,
): Promise<RuleGenerationOutput> {
  const evidence = buildRuleEvidence(state, "yara");
  if (!evidence.sufficient) {
    return { kind: "yara", status: "skipped", rules: [], reason: evidence.reason };
  }

  const now = options.now?.() ?? new Date();
  let draft: YaraGenerationDraft;
  try {
    draft = await options.model.generateObject({
      system: YARA_SYSTEM_PROMPT,
      prompt: buildYaraPrompt(evidence, now),
      schema: yaraGenerationDraftSchema,
      temperature: 0.1,
      maxOutputTokens: 4_096,
      ...(options.signal ? { abortSignal: options.signal } : {}),
    });
  } catch (error) {
    const message = `YARA generation failed: ${messageOf(error)}`;
    options.logger?.warn({ error: message }, "yara generation failed");
    return { kind: "yara", status: "invalid", rules: [], reason: message, error: message };
  }

  const rules: RuleArtifact[] = [];
  for (const rule of draft.rules) {
    if (rule.rule_text.trim().length === 0) {
      continue;
    }
    const refs = resolveRefs(rule.evidence_refs, evidence);
    const validation = await validateYara(rule.rule_text);
    const groundingErrors =
      validation.status === "valid" ? yaraGroundingErrors(rule.rule_text, evidence.formatted) : [];
    const validationErrors = [...refs.errors, ...validation.errors, ...groundingErrors];
    let status: RuleArtifact["status"];
    if (refs.refs.length === 0) {
      status = "invalid";
      validationErrors.push("No valid evidence_ref was cited for this rule.");
    } else if (validation.status === "valid" && groundingErrors.length === 0) {
      status = "valid";
    } else if (validation.status === "unavailable") {
      status = "generated";
    } else {
      status = "invalid";
    }

    rules.push(
      artifact({
        kind: "yara",
        content: rule.rule_text,
        name: validation.ruleNames[0] ?? rule.rule_name,
        description: rule.description,
        tags: rule.tags,
        reasoning: rule.reasoning,
        status,
        validationErrors,
        evidenceRefs: refs.refs,
        createdAt: now.toISOString(),
      }),
    );
  }

  const unique = dedupeRules(rules);
  const status = overallStatus(unique);
  const failed = unique.filter((rule) => rule.status === "invalid").length;
  return {
    kind: "yara",
    status,
    rules: unique,
    reason:
      draft.reasoning ||
      (status === "skipped" ? "Model returned no YARA rules." : "YARA rules generated."),
    ...(failed > 0 ? { error: `${failed} YARA rule(s) failed validation.` } : {}),
  };
}

export async function generateSigmaRules(
  state: AnalysisState,
  options: RuleGenerationOptions,
): Promise<RuleGenerationOutput> {
  const evidence = buildRuleEvidence(state, "sigma");
  if (!evidence.sufficient) {
    return { kind: "sigma", status: "skipped", rules: [], reason: evidence.reason };
  }

  const now = options.now?.() ?? new Date();
  let draft: SigmaGenerationDraft;
  try {
    draft = await options.model.generateObject({
      system: SIGMA_SYSTEM_PROMPT,
      prompt: buildSigmaPrompt(evidence, now),
      schema: sigmaGenerationDraftSchema,
      temperature: 0.1,
      maxOutputTokens: 4_096,
      ...(options.signal ? { abortSignal: options.signal } : {}),
    });
  } catch (error) {
    const message = `SIGMA generation failed: ${messageOf(error)}`;
    options.logger?.warn({ error: message }, "sigma generation failed");
    return { kind: "sigma", status: "invalid", rules: [], reason: message, error: message };
  }

  const rules: RuleArtifact[] = [];
  for (const rule of draft.rules) {
    if (rule.rule_text.trim().length === 0) {
      continue;
    }
    const refs = resolveRefs(rule.evidence_refs, evidence);
    const validation = validateSigma(rule.rule_text);
    const groundingErrors =
      validation.status === "valid" ? sigmaGroundingErrors(rule.rule_text, evidence.formatted) : [];
    const validationErrors = [...refs.errors, ...validation.errors, ...groundingErrors];
    let status: RuleArtifact["status"];
    if (refs.refs.length === 0) {
      status = "invalid";
      validationErrors.push("No valid evidence_ref was cited for this rule.");
    } else if (validation.status === "valid" && groundingErrors.length === 0) {
      status = "valid";
    } else {
      status = "invalid";
    }

    rules.push(
      artifact({
        kind: "sigma",
        content: rule.rule_text,
        name: validation.title ?? rule.rule_name,
        description: rule.description,
        tags: rule.tags,
        reasoning: rule.reasoning,
        status,
        validationErrors,
        evidenceRefs: refs.refs,
        createdAt: now.toISOString(),
      }),
    );
  }

  const unique = dedupeRules(rules);
  const status = overallStatus(unique);
  const failed = unique.filter((rule) => rule.status === "invalid").length;
  return {
    kind: "sigma",
    status,
    rules: unique,
    reason:
      draft.reasoning ||
      (status === "skipped" ? "Model returned no SIGMA rules." : "SIGMA rules generated."),
    ...(failed > 0 ? { error: `${failed} SIGMA rule(s) failed validation.` } : {}),
  };
}
