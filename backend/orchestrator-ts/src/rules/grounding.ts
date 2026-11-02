import { parse } from "yaml";

const CONCRETE_INDICATOR_RE =
  /https?:\/\/|(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,10}|\b[a-f0-9]{32,64}\b|\.(?:exe|dll|docm|doc|xlsm|ps1|bat|cmd|js|vbs)\b/i;

function yaraStringLiterals(source: string): string[] {
  const section = source.match(/\bstrings\s*:\s*([\s\S]*?)\bcondition\s*:/i);
  if (!section?.[1]) {
    return [];
  }
  return [...section[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)]
    .map((match) => match[1] ?? "")
    .filter((literal) => literal.length >= 4);
}

function unescapeYaraLiteral(value: string): string {
  return value
    .replaceAll('\\"', '"')
    .replaceAll("\\\\", "\\")
    .replaceAll("\\n", "\n")
    .replaceAll("\\t", "\t")
    .replaceAll("\\r", "\r");
}

/**
 * Enforce that YARA string literals are grounded in the evidence packet. YARA
 * syntax validation alone cannot prove the model did not invent a string.
 */
export function yaraGroundingErrors(source: string, evidenceText: string): string[] {
  const errors: string[] = [];
  for (const literal of yaraStringLiterals(source)) {
    const unescaped = unescapeYaraLiteral(literal);
    if (!evidenceText.includes(literal) && !evidenceText.includes(unescaped)) {
      errors.push(`YARA string "${literal}" is not present in the supplied evidence.`);
    }
  }
  return errors.slice(0, 20);
}

function collectConcreteValues(value: unknown, output: string[] = []): string[] {
  if (typeof value === "string") {
    if (CONCRETE_INDICATOR_RE.test(value)) {
      output.push(value);
    }
  } else if (Array.isArray(value)) {
    for (const item of value) {
      collectConcreteValues(item, output);
    }
  } else if (typeof value === "object" && value !== null) {
    for (const entry of Object.values(value)) {
      collectConcreteValues(entry, output);
    }
  }
  return output;
}

/**
 * Enforce that concrete SIGMA detection values (URLs, IPs, domains, hashes and
 * executable/document filenames) appear in the evidence packet.
 */
export function sigmaGroundingErrors(source: string, evidenceText: string): string[] {
  let document: unknown;
  try {
    document = parse(source);
  } catch {
    return [];
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return [];
  }
  const detection = (document as Record<string, unknown>).detection;
  if (typeof detection !== "object" || detection === null || Array.isArray(detection)) {
    return [];
  }

  const values = Object.entries(detection as Record<string, unknown>)
    .filter(([key]) => key !== "condition")
    .flatMap(([, value]) => collectConcreteValues(value));
  const errors: string[] = [];
  for (const value of values) {
    if (!evidenceText.toLowerCase().includes(value.toLowerCase())) {
      errors.push(`SIGMA detection value "${value}" is not present in the supplied evidence.`);
    }
  }
  return [...new Set(errors)].slice(0, 20);
}
