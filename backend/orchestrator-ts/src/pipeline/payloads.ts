import { rename } from "node:fs/promises";
import path from "node:path";

import type { AnalyzerName } from "../config.js";
import { extractArtifacts } from "../graph/artifacts.js";
import type { SecFlowResult } from "../graph/schema/analyzer.js";

export type FileAnalyzerName = Extract<AnalyzerName, "malware" | "macro" | "steg">;

/** Mirrors the Python orchestrator's download-and-analyze selection tables. */
export const CONTENT_TYPE_TO_ANALYZER: Readonly<Record<string, FileAnalyzerName>> = {
  "application/x-executable": "malware",
  "application/x-dosexec": "malware",
  "application/x-msdos-program": "malware",
  "application/x-elf": "malware",
  "application/vnd.microsoft.portable-executable": "malware",
  "application/octet-stream": "malware",
  "application/x-sharedlib": "malware",
  "application/x-pie-executable": "malware",
  "application/msword": "macro",
  "application/vnd.ms-excel": "macro",
  "application/vnd.ms-powerpoint": "macro",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "macro",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "macro",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation": "macro",
  "application/vnd.ms-excel.sheet.macroEnabled.12": "macro",
  "application/rtf": "macro",
  "image/png": "steg",
  "image/jpeg": "steg",
  "image/gif": "steg",
  "image/bmp": "steg",
  "image/webp": "steg",
  "image/tiff": "steg",
};

export const URL_EXTENSION_TO_ANALYZER: Readonly<Record<string, FileAnalyzerName>> = {
  ".exe": "malware",
  ".dll": "malware",
  ".elf": "malware",
  ".bin": "malware",
  ".so": "malware",
  ".out": "malware",
  ".o": "malware",
  ".doc": "macro",
  ".docx": "macro",
  ".xls": "macro",
  ".xlsx": "macro",
  ".xlsm": "macro",
  ".docm": "macro",
  ".ppt": "macro",
  ".pptx": "macro",
  ".pptm": "macro",
  ".rtf": "macro",
  ".png": "steg",
  ".jpg": "steg",
  ".jpeg": "steg",
  ".gif": "steg",
  ".bmp": "steg",
};

const SKIP_CONTENT_TYPES = new Set([
  "text/html",
  "text/plain",
  "text/css",
  "text/javascript",
  "application/javascript",
  "application/json",
]);

const ANALYZER_EXTENSIONS: Readonly<Record<FileAnalyzerName, readonly string[]>> = {
  malware: [".exe", ".dll", ".so", ".elf", ".bin", ".o", ".out"],
  macro: [".doc", ".docx", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx", ".pptm", ".docm", ".rtf"],
  steg: [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff"],
};

const DEFAULT_EXTENSION: Readonly<Record<FileAnalyzerName, string>> = {
  malware: ".bin",
  macro: ".doc",
  steg: ".png",
};

function normalizeContentType(contentType: string): string {
  return contentType.split(";")[0]?.trim().toLowerCase() ?? "";
}

export function shouldSkipDownloadContentType(contentType: string): boolean {
  return SKIP_CONTENT_TYPES.has(normalizeContentType(contentType));
}

export function selectAnalyzerForDownload(
  url: string,
  contentType: string,
): FileAnalyzerName | null {
  const byContentType = CONTENT_TYPE_TO_ANALYZER[normalizeContentType(contentType)];
  if (byContentType) {
    return byContentType;
  }
  try {
    const extension = path.extname(new URL(url).pathname).toLowerCase();
    return URL_EXTENSION_TO_ANALYZER[extension] ?? null;
  } catch {
    return null;
  }
}

function safePayloadName(raw: string): string {
  const base = path.basename(raw).replace(/[^A-Za-z0-9._-]/g, "_");
  return base.replace(/^\.+/, "").slice(-120) || "payload";
}

/** A model/report-safe name that still carries the extension the analyzer expects. */
export function payloadDisplayName(url: string, analyzer: FileAnalyzerName): string {
  let rawName = "payload";
  try {
    const parsed = new URL(url);
    rawName = decodeURIComponent(path.basename(parsed.pathname)) || "payload";
  } catch {
    // Keep the fallback name; the URL was already validated before download.
  }

  const safe = safePayloadName(rawName);
  const currentExtension = path.extname(safe).toLowerCase();
  if (ANALYZER_EXTENSIONS[analyzer].includes(currentExtension)) {
    return safe;
  }
  const stem = path.basename(safe, currentExtension) || "payload";
  return `${stem}${DEFAULT_EXTENSION[analyzer]}`;
}

/**
 * Keep the temp path acceptable to the analyzer's extension validation. The
 * display name is handled separately because it is what the model/report sees.
 */
export async function ensureAnalyzerFileExtension(
  filePath: string,
  analyzer: FileAnalyzerName,
): Promise<string> {
  const currentExtension = path.extname(filePath).toLowerCase();
  if (ANALYZER_EXTENSIONS[analyzer].includes(currentExtension)) {
    return filePath;
  }
  const nextPath = `${filePath}${DEFAULT_EXTENSION[analyzer]}`;
  await rename(filePath, nextPath);
  return nextPath;
}

/** Known payload extensions first, matching the Python caller's ordering. */
export function findPayloadCandidates(
  result: SecFlowResult,
  downloadedUrls: ReadonlySet<string>,
): string[] {
  const urls = extractArtifacts(result).urls.filter((url) => !downloadedUrls.has(url));
  const known = urls.filter((url) => {
    try {
      return URL_EXTENSION_TO_ANALYZER[path.extname(new URL(url).pathname).toLowerCase()] !== undefined;
    } catch {
      return false;
    }
  });
  const knownSet = new Set(known);
  return [...known, ...urls.filter((url) => !knownSet.has(url))];
}
