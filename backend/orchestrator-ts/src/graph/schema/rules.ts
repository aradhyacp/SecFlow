import { z } from "zod";

export const RULE_KINDS = ["yara", "sigma"] as const;
export const ruleKindSchema = z.enum(RULE_KINDS);
export type RuleKind = z.infer<typeof ruleKindSchema>;

export const RULE_STATUSES = ["generated", "valid", "invalid", "skipped"] as const;
export const ruleStatusSchema = z.enum(RULE_STATUSES);
export type RuleStatus = z.infer<typeof ruleStatusSchema>;

export const ruleArtifactSchema = z
  .object({
    id: z.string().regex(/^rule_[a-f0-9]{16}$/),
    kind: ruleKindSchema,
    /** Detected rule/title name; derived from the validated content. */
    name: z.string().min(1).max(200).optional(),
    description: z.string().max(2_000).optional(),
    tags: z.array(z.string().max(100)).max(50).default([]),
    content: z.string().min(1).max(200_000),
    reasoning: z.string().max(10_000),
    status: ruleStatusSchema,
    validationErrors: z.array(z.string().max(2_000)).max(100).default([]),
    /** Analyzer/pass references plus raw-output refs the rule was derived from. */
    evidenceRefs: z.array(z.string().max(200)).max(100).default([]),
    createdAt: z.string().datetime(),
  })
  .strict();
export type RuleArtifact = z.infer<typeof ruleArtifactSchema>;

export const rulesStateSchema = z
  .object({
    yara: z.array(ruleArtifactSchema).max(50).default([]),
    sigma: z.array(ruleArtifactSchema).max(50).default([]),
    /** Set when generation was skipped because the evidence gate was not met. */
    skipReason: z.string().max(2_000).optional(),
  })
  .strict();
export type RulesState = z.infer<typeof rulesStateSchema>;

export const ruleGenerationOutputSchema = z
  .object({
    kind: ruleKindSchema,
    status: z.enum(["generated", "skipped", "invalid"]),
    rules: z.array(ruleArtifactSchema).max(50),
    reason: z.string().max(2_000).optional(),
    /** Present when the generation call itself failed (as opposed to a skip). */
    error: z.string().max(4_000).optional(),
  })
  .strict();
export type RuleGenerationOutput = z.infer<typeof ruleGenerationOutputSchema>;
