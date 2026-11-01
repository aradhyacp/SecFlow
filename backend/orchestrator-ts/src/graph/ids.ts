import { createHash } from "node:crypto";

function stableDigest(parts: readonly string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 16);
}

export function makeTargetId(kind: string, value: string): string {
  return `tgt_${stableDigest([kind, value])}`;
}

export function makeIndicatorId(kind: string, value: string): string {
  return `ioc_${stableDigest([kind, value])}`;
}

export function makeRuleId(kind: string, content: string): string {
  return `rule_${stableDigest([kind, content])}`;
}

export function makeToolRecordId(tool: string, targetId: string, sequence: number): string {
  return `tool_${stableDigest([tool, targetId, String(sequence)])}`;
}

export function makeErrorId(stage: string, message: string, sequence: number): string {
  return `err_${stableDigest([stage, message, String(sequence)])}`;
}

export function makeRawOutputId(analyzer: string, pass: number, content: string): string {
  return `raw_${stableDigest([analyzer, String(pass), content])}`;
}
