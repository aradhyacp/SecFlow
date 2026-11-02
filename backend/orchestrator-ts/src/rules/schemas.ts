import { z } from "zod";

export const yaraRuleDraftSchema = z
  .object({
    rule_name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,99}$/),
    description: z.string().min(1).max(1_000),
    reasoning: z.string().min(1).max(4_000),
    tags: z.array(z.string().min(1).max(100)).max(30).default([]),
    evidence_refs: z.array(z.string().min(1).max(200)).min(1).max(30),
    rule_text: z.string().min(1).max(200_000),
  })
  .strict();

export const yaraGenerationDraftSchema = z
  .object({
    reasoning: z.string().min(1).max(4_000),
    rules: z.array(yaraRuleDraftSchema).max(10),
  })
  .strict();
export type YaraGenerationDraft = z.infer<typeof yaraGenerationDraftSchema>;

export const sigmaRuleDraftSchema = z
  .object({
    rule_name: z.string().min(1).max(200),
    description: z.string().min(1).max(1_000),
    log_source: z.string().min(1).max(200),
    reasoning: z.string().min(1).max(4_000),
    tags: z.array(z.string().min(1).max(100)).max(30).default([]),
    evidence_refs: z.array(z.string().min(1).max(200)).min(1).max(30),
    rule_text: z.string().min(1).max(200_000),
  })
  .strict();

export const sigmaGenerationDraftSchema = z
  .object({
    reasoning: z.string().min(1).max(4_000),
    rules: z.array(sigmaRuleDraftSchema).max(10),
  })
  .strict();
export type SigmaGenerationDraft = z.infer<typeof sigmaGenerationDraftSchema>;

export type RuleDraft =
  YaraGenerationDraft["rules"][number] | SigmaGenerationDraft["rules"][number];
