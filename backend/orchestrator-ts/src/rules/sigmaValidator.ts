import { parse } from "yaml";

export type SigmaValidationStatus = "valid" | "invalid";

export interface SigmaValidationResult {
  status: SigmaValidationStatus;
  errors: string[];
  warnings: string[];
  title?: string;
  logSource?: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const LEVELS = new Set(["critical", "high", "medium", "low", "informational"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Structural SIGMA validation. This checks the required fields and shapes that
 * a SIGMA-compatible SIEM needs; it is not a pySigma backend conversion.
 */
export function validateSigma(source: string): SigmaValidationResult {
  let document: unknown;
  try {
    document = parse(source);
  } catch (error) {
    return {
      status: "invalid",
      errors: [`YAML parse error: ${error instanceof Error ? error.message : String(error)}`],
      warnings: [],
    };
  }

  if (!isRecord(document)) {
    return {
      status: "invalid",
      errors: ["SIGMA rule must be a YAML mapping"],
      warnings: [],
    };
  }

  const errors: string[] = [];
  const warnings: string[] = [];
  const title = typeof document.title === "string" ? document.title.trim() : "";
  if (!title) {
    errors.push("title must be a non-empty string");
  }

  if (typeof document.id !== "string" || !UUID_RE.test(document.id)) {
    errors.push("id must be a valid UUID");
  }

  const logsource = isRecord(document.logsource) ? document.logsource : undefined;
  if (!logsource) {
    errors.push("logsource must be a mapping");
  } else {
    const sources = ["category", "product", "service"].filter(
      (key) => typeof logsource[key] === "string" && Boolean(logsource[key]),
    );
    if (sources.length === 0) {
      errors.push("logsource must define category, product, or service");
    }
  }

  if (!isRecord(document.detection)) {
    errors.push("detection must be a mapping");
  } else {
    if (typeof document.detection.condition !== "string" || !document.detection.condition) {
      errors.push("detection.condition must be a non-empty string");
    }
    const selections = Object.keys(document.detection).filter((key) => key !== "condition");
    if (selections.length === 0) {
      errors.push("detection must define at least one selection");
    }
  }

  if (document.level !== undefined) {
    if (typeof document.level !== "string" || !LEVELS.has(document.level.toLowerCase())) {
      errors.push("level must be critical, high, medium, low, or informational");
    }
  } else {
    warnings.push("level is not set");
  }

  const logSourceKey = logsource
    ? ["category", "product", "service"].find(
        (key) => typeof logsource[key] === "string" && Boolean(logsource[key]),
      )
    : undefined;
  const logSourceValue = logsource && logSourceKey ? String(logsource[logSourceKey]) : undefined;

  return {
    status: errors.length === 0 ? "valid" : "invalid",
    errors,
    warnings,
    ...(title ? { title } : {}),
    ...(logSourceValue ? { logSource: logSourceValue } : {}),
  };
}
