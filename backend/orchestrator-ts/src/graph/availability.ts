import type { AnalysisTarget, Classification, ToolHistoryEntry } from "./state.js";
import { analysisToolNames, type AnalysisToolName } from "./schema/tools.js";

export type FileSubtype = "image" | "document" | "executable" | "unknown";

export interface AvailableAction {
  tool: AnalysisToolName;
  targetId: string;
}

export interface AvailabilityInput {
  targets: readonly AnalysisTarget[];
  classification: Classification;
  primaryTargetId: string;
  registeredTools: readonly string[];
  history: readonly ToolHistoryEntry[];
}

const IMAGE_EXTENSIONS = /\.(png|jpe?g|gif|bmp|tiff?|webp)$/i;
const DOCUMENT_EXTENSIONS = /\.(docx?|xlsx?|pptx?|xlsm|docm|pptm|xlsb|rtf)$/i;
const EXECUTABLE_EXTENSIONS = /\.(exe|dll|so|elf|bin|o|out)$/i;

function mimeIs(target: AnalysisTarget, prefix: string): boolean {
  return target.mimeType?.toLowerCase().startsWith(prefix) === true;
}

/**
 * Decide which analyzer family a file target belongs to. The original input
 * uses the deterministic classifier's verdict; later file artifacts fall back
 * to MIME type and extension.
 */
export function inferFileSubtype(
  target: AnalysisTarget,
  classification: Classification,
  primaryTargetId: string,
): FileSubtype {
  if (target.id === primaryTargetId) {
    if (classification.inputType === "image") return "image";
    if (classification.inputType === "document") return "document";
    if (classification.inputType === "executable") return "executable";
  }

  if (mimeIs(target, "image/")) return "image";
  if (IMAGE_EXTENSIONS.test(target.displayName)) return "image";

  if (
    mimeIs(target, "application/msword") ||
    mimeIs(target, "application/vnd.ms-") ||
    mimeIs(target, "application/vnd.openxmlformats-officedocument") ||
    mimeIs(target, "application/rtf") ||
    mimeIs(target, "text/rtf") ||
    mimeIs(target, "application/x-cfb")
  ) {
    return "document";
  }
  if (DOCUMENT_EXTENSIONS.test(target.displayName)) return "document";

  if (
    mimeIs(target, "application/x-executable") ||
    mimeIs(target, "application/x-dosexec") ||
    mimeIs(target, "application/x-msdos-program") ||
    mimeIs(target, "application/x-elf") ||
    mimeIs(target, "application/x-mach-binary") ||
    mimeIs(target, "application/x-sharedlib") ||
    mimeIs(target, "application/x-pie-executable") ||
    mimeIs(target, "application/vnd.microsoft.portable-executable")
  ) {
    return "executable";
  }
  if (EXECUTABLE_EXTENSIONS.test(target.displayName)) return "executable";

  return "unknown";
}

const FILE_TOOLS: Record<Exclude<FileSubtype, "unknown">, AnalysisToolName> = {
  image: "analyze_steg",
  document: "analyze_macro",
  executable: "analyze_malware",
};

/** Tools that can legally analyze this target. Unknown file types may be any. */
export function toolsForTarget(
  target: AnalysisTarget,
  classification: Classification,
  primaryTargetId: string,
): AnalysisToolName[] {
  switch (target.kind) {
    case "url":
      return ["analyze_web"];
    case "ip":
    case "domain":
    case "email":
    case "phone":
    case "username":
      return ["analyze_recon"];
    case "file": {
      const subtype = inferFileSubtype(target, classification, primaryTargetId);
      if (subtype === "unknown") {
        return ["analyze_malware", "analyze_steg", "analyze_macro"];
      }
      return [FILE_TOOLS[subtype]];
    }
    default:
      return [];
  }
}

/**
 * The action allowlist for the next decision. Pairs that have already been
 * attempted (success, failure or rejection) are removed so the model cannot
 * request an identical call twice.
 */
export function buildAvailableActions(input: AvailabilityInput): AvailableAction[] {
  const registered = new Set(input.registeredTools);
  const attempted = new Set(
    input.history
      .filter((entry) => entry.targetId !== undefined)
      .map((entry) => `${entry.tool}:${entry.targetId}`),
  );

  const actions: AvailableAction[] = [];
  for (const target of input.targets) {
    for (const tool of toolsForTarget(target, input.classification, input.primaryTargetId)) {
      if (!registered.has(tool)) {
        continue;
      }
      if (attempted.has(`${tool}:${target.id}`)) {
        continue;
      }
      actions.push({ tool, targetId: target.id });
    }
  }

  const order = new Map(analysisToolNames.map((tool, index) => [tool, index]));
  return actions.sort(
    (left, right) =>
      (order.get(left.tool) ?? 99) - (order.get(right.tool) ?? 99) ||
      left.targetId.localeCompare(right.targetId),
  );
}

export function availableToolNames(actions: readonly AvailableAction[]): AnalysisToolName[] {
  const seen = new Set<AnalysisToolName>();
  for (const action of actions) {
    seen.add(action.tool);
  }
  return analysisToolNames.filter((tool) => seen.has(tool));
}
