import type { AdaptedAnalyzerResult } from "../types.js";
import type { SecFlowFinding } from "../../graph/schema/analyzer.js";
import { severityRiskScore } from "../../graph/schema/analyzer.js";
import { asArray, asRecord, asString, joinRaw, jsonDumps, truncate } from "../parse.js";

const HIGH_SEVERITY_TOOLS = new Set([
  "binwalk",
  "foremost",
  "steghide",
  "outguess",
  "zsteg",
  "jsteg",
  "jpseek",
]);
const MEDIUM_SEVERITY_TOOLS = new Set(["strings", "openstego"]);

function hasContent(value: unknown): boolean {
  if (typeof value === "string") {
    return value.length > 0;
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (value && typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return false;
}

function severityForTool(
  toolName: string,
  result: Record<string, unknown>,
): SecFlowFinding["severity"] {
  if (asString(result.status, "error") !== "ok") {
    return "info";
  }
  if (!hasContent(result.output) && !hasContent(result.download)) {
    return "info";
  }

  const tool = toolName.toLowerCase();
  if (HIGH_SEVERITY_TOOLS.has(tool)) {
    return hasContent(result.download) ? "critical" : "high";
  }
  if (MEDIUM_SEVERITY_TOOLS.has(tool)) {
    return "medium";
  }
  return "low";
}

/**
 * Translate a steg-analyzer result payload into the SecFlow contract.
 * Mirrors backend/orchestrator/app/adapters/steg_adapter.py.
 */
export function adaptSteg(payload: unknown): AdaptedAnalyzerResult {
  const findings: SecFlowFinding[] = [];
  const rawParts: string[] = [];
  const extractedFiles: string[] = [];
  const results = asRecord(asRecord(payload).results);

  for (const [toolName, rawToolResult] of Object.entries(results)) {
    if (!rawToolResult || typeof rawToolResult !== "object" || Array.isArray(rawToolResult)) {
      continue;
    }
    const toolResult = rawToolResult as Record<string, unknown>;
    const status = asString(toolResult.status, "error");
    rawParts.push(`[${toolName}] status=${status}`);

    if (status === "error") {
      rawParts.push(`  error: ${asString(toolResult.error, "unknown error")}`);
      continue;
    }

    const output = toolResult.output;
    const note = asString(toolResult.note);
    const download = asString(toolResult.download);

    if (hasContent(output)) {
      rawParts.push(
        `  output: ${truncate(typeof output === "string" ? output : jsonDumps(output), 500)}`,
      );
    }
    if (download) {
      rawParts.push(`  download: ${download}`);
      extractedFiles.push(download);
    }

    const severity = severityForTool(toolName, toolResult);
    if (severity === "critical" || severity === "high" || severity === "medium") {
      const detailParts = [`${toolName} detected steganographic content`];
      if (note) {
        detailParts.push(note);
      }
      findings.push({
        type: "steg_detection",
        detail: detailParts.join(" — "),
        severity,
        evidence: `${hasContent(output) ? truncate(jsonDumps(output), 400) : ""}${
          download ? `\ndownload: ${download}` : ""
        }`,
        extracted_path: download || null,
      });
    } else if (hasContent(output)) {
      findings.push({
        type: "steg_info",
        detail: `${toolName}: analysis complete`,
        severity: "info",
        evidence: hasContent(output) ? truncate(jsonDumps(output), 200) : "",
        extracted_path: null,
      });
    }
  }

  return {
    findings,
    riskScore: severityRiskScore(findings),
    rawOutput: joinRaw(rawParts),
    extractedFiles,
  };
}

export function countStegResults(payload: unknown): number {
  return asArray(asRecord(asRecord(payload).results)).length;
}
