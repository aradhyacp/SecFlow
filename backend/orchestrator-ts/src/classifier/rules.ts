import type { AnalyzerName } from "../config.js";
import type { InputType } from "../graph/state.js";

export interface RuleMatch {
  analyzer: AnalyzerName;
  inputType: Exclude<InputType, "unknown">;
  reason: string;
}

export interface StringRuleMatch extends RuleMatch {
  analyzer: "recon" | "web";
  inputType: "url" | "ip" | "domain" | "email" | "phone";
}

const URL_REGEX = /^https?:\/\//i;
const IP_REGEX =
  /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const DOMAIN_REGEX = /^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/;
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const PHONE_REGEX = /^\+?[0-9]\d{1,14}$/;

const DOCUMENT_MIME_TYPES = new Set([
  "application/msword",
  "application/vnd.ms-excel",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.ms-excel.sheet.macroEnabled.12",
  "application/vnd.ms-word.document.macroEnabled.12",
  "application/rtf",
  "text/rtf",
  "application/vnd.ms-office",
  "application/x-cfb",
]);

const DOCUMENT_EXTENSIONS = [
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".xlsm",
  ".xlsb",
  ".ppt",
  ".pptx",
  ".pptm",
  ".docm",
  ".rtf",
] as const;

const EXECUTABLE_MIME_TYPES = new Set([
  "application/x-executable",
  "application/x-dosexec",
  "application/x-msdos-program",
  "application/x-elf",
  "application/x-mach-binary",
  "application/x-sharedlib",
  "application/x-pie-executable",
  "application/vnd.microsoft.portable-executable",
  "application/octet-stream",
]);

const EXECUTABLE_MAGIC_KEYWORDS = ["PE32", "ELF", "Mach-O", "MS-DOS", "MS Windows"];

function looksLikeUrl(value: string): boolean {
  if (!URL_REGEX.test(value)) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (
      parsed.hostname.length > 0 && (parsed.protocol === "http:" || parsed.protocol === "https:")
    );
  } catch {
    return false;
  }
}

/**
 * Deterministic rules for string inputs. URL must be checked before domain so
 * `https://example.com` is not routed as a bare domain.
 */
export function classifyString(rawValue: string): StringRuleMatch | null {
  const value = rawValue.trim();
  if (value.length === 0) {
    return null;
  }

  if (looksLikeUrl(value)) {
    return { analyzer: "web", inputType: "url", reason: "matched http(s) URL rule" };
  }
  if (IP_REGEX.test(value)) {
    return { analyzer: "recon", inputType: "ip", reason: "matched IPv4 rule" };
  }
  if (DOMAIN_REGEX.test(value)) {
    return { analyzer: "recon", inputType: "domain", reason: "matched domain rule" };
  }
  if (EMAIL_REGEX.test(value)) {
    return { analyzer: "recon", inputType: "email", reason: "matched email rule" };
  }
  if (PHONE_REGEX.test(value) && value.replace(/\D/g, "").length >= 7) {
    return { analyzer: "recon", inputType: "phone", reason: "matched phone rule" };
  }
  return null;
}

/**
 * Deterministic file rules, in the same order as the Python classifier:
 * image → Office/RTF document → executable.
 */
export function classifyFile(
  mimeType: string,
  magicOutput: string,
  fileName: string,
): RuleMatch | null {
  const mime = mimeType.toLowerCase().split(";")[0]?.trim() ?? "";
  const magic = magicOutput.toUpperCase();
  const lowerName = fileName.toLowerCase();

  if (
    mime.startsWith("image/") ||
    ["PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP"].some((keyword) => magic.includes(keyword))
  ) {
    return { analyzer: "steg", inputType: "image", reason: "matched image signature" };
  }

  if (
    DOCUMENT_MIME_TYPES.has(mime) ||
    [
      "COMPOSITE DOCUMENT FILE V2",
      "MICROSOFT OFFICE",
      "MICROSOFT WORD",
      "MICROSOFT EXCEL",
      "MICROSOFT POWERPOINT",
      "OFFICE OPEN XML",
      "RICH TEXT FORMAT",
    ].some((keyword) => magic.includes(keyword)) ||
    (mime === "application/zip" &&
      DOCUMENT_EXTENSIONS.some((extension) => lowerName.endsWith(extension)))
  ) {
    return { analyzer: "macro", inputType: "document", reason: "matched Office/RTF document rule" };
  }

  const executableMagic = EXECUTABLE_MAGIC_KEYWORDS.some((keyword) =>
    magicOutput.includes(keyword),
  );
  if (
    (EXECUTABLE_MIME_TYPES.has(mime) && executableMagic) ||
    (executableMagic &&
      ["PE32", "ELF", "MACH-O", "MS-DOS EXECUTABLE"].some((k) => magic.includes(k)))
  ) {
    return { analyzer: "malware", inputType: "executable", reason: "matched executable signature" };
  }

  return null;
}

export const INPUT_RULES = {
  URL_REGEX,
  IP_REGEX,
  DOMAIN_REGEX,
  EMAIL_REGEX,
  PHONE_REGEX,
  DOCUMENT_MIME_TYPES,
  DOCUMENT_EXTENSIONS,
  EXECUTABLE_MIME_TYPES,
} as const;
