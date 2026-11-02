import { makeIndicatorId, makeTargetId } from "./ids.js";
import type { Indicator, AnalysisTarget } from "./state.js";
import type { SecFlowResult } from "./schema/analyzer.js";

const MAX_ARTIFACT_TEXT = 1_000_000;
const MAX_NEW_TARGETS = 20;

const URL_REGEX = /https?:\/\/[^\s"'<>(),\\}]+/g;
const IP_REGEX = /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b/g;
const DOMAIN_REGEX = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}\b/g;

/** Library/toolchain domains that would create noise passes. Mirrors Python. */
const DOMAIN_NOISE = new Set([
  "gnu.org",
  "github.com",
  "ubuntu.com",
  "debian.org",
  "so.1",
  "so.2",
  "so.3",
  "so.6",
  "glibc.so",
  "libc.so",
  "apt.org",
  "pypi.org",
  "python.org",
  "localhost",
  "example.com",
  "test.com",
]);

export interface ExtractedArtifacts {
  urls: string[];
  ips: string[];
  domains: string[];
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

function extractFromText(text: string): ExtractedArtifacts {
  const urls = unique([...text.matchAll(URL_REGEX)].map((match) => match[0].replace(/[/.]+$/, "")));
  const ips = unique([...text.matchAll(IP_REGEX)].map((match) => match[0]));
  const ipSet = new Set(ips);
  const domains = unique([...text.matchAll(DOMAIN_REGEX)].map((match) => match[0])).filter(
    (domain) =>
      !ipSet.has(domain) &&
      !DOMAIN_NOISE.has(domain.toLowerCase()) &&
      !domain.toLowerCase().endsWith(".so") &&
      !domain.toLowerCase().endsWith(".o") &&
      domain.length > 4,
  );

  for (const url of urls) {
    try {
      const host = new URL(url).hostname;
      if (host && !ipSet.has(host) && !DOMAIN_NOISE.has(host.toLowerCase())) {
        domains.unshift(host);
      }
    } catch {
      // Ignore malformed URLs; the target builder validates them again.
    }
  }

  return {
    urls: unique(urls).slice(0, 10),
    ips: ips.slice(0, 5),
    domains: unique(domains).slice(0, 10),
  };
}

function validSchemeFragment(fragment: string): boolean {
  return /^https?:\/\//i.test(fragment);
}

function validHost(host: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(host);
}

/**
 * Reconstruct C string literals from Ghidra output where a URL is split across
 * adjacent literals (`"https://"` + `"host"` + `"/path"`). Mirrors Python.
 */
function grepCStrings(text: string): string {
  const fragments = [...text.matchAll(/"([^"\n\\]{1,})"/g)].map((match) => match[1] ?? "");
  const stitched: string[] = [];
  let index = 0;

  while (index < fragments.length) {
    const fragment = fragments[index] ?? "";
    if (validSchemeFragment(fragment)) {
      let combined = fragment;
      let next = index + 1;
      while (next < fragments.length && combined.length < 300) {
        combined += fragments[next] ?? "";
        next += 1;
        try {
          const host = new URL(combined).hostname;
          if (validHost(host)) {
            break;
          }
        } catch {
          // Keep appending until a valid URL or the fragment cap.
        }
      }
      stitched.push(combined);
      index = next;
    } else {
      if (fragment.length >= 4) {
        stitched.push(fragment);
      }
      index += 1;
    }
  }

  return stitched.join("\n");
}

/** Three-layer extraction: raw output, reconstructed C strings, findings evidence. */
export function extractArtifacts(result: SecFlowResult): ExtractedArtifacts {
  const rawOutput = result.raw_output.slice(0, MAX_ARTIFACT_TEXT);
  const evidence = result.findings
    .map((finding) => finding.evidence ?? "")
    .filter((value) => value.length > 0)
    .join("\n")
    .slice(0, MAX_ARTIFACT_TEXT);

  const first = extractFromText(rawOutput);
  const cStrings = grepCStrings(rawOutput);
  const second =
    cStrings.trim().length > 0 ? extractFromText(cStrings) : { urls: [], ips: [], domains: [] };
  const third =
    evidence.trim().length > 0 ? extractFromText(evidence) : { urls: [], ips: [], domains: [] };

  return {
    urls: unique([...first.urls, ...second.urls, ...third.urls]).slice(0, 10),
    ips: unique([...first.ips, ...second.ips, ...third.ips]).slice(0, 5),
    domains: unique([...first.domains, ...second.domains, ...third.domains]).slice(0, 10),
  };
}

function displayName(value: string): string {
  return value.length > 1_024 ? value.slice(0, 1_024) : value;
}

/**
 * Turn extracted indicators into trusted targets and provenance records. Only
 * network indicators are promoted; file paths from analyzer output are never
 * accepted as targets.
 */
export function buildArtifactTargets(
  result: SecFlowResult,
  existingTargets: readonly AnalysisTarget[],
  existingIndicators: readonly Indicator[],
): { targets: AnalysisTarget[]; indicators: Indicator[] } {
  const extracted = extractArtifacts(result);
  const knownTargets = new Set(existingTargets.map((target) => `${target.kind}:${target.value}`));
  const knownIndicators = new Set(existingIndicators.map((indicator) => indicator.id));
  const targets: AnalysisTarget[] = [];
  const indicators: Indicator[] = [];

  const add = (kind: "url" | "ip" | "domain", value: string): void => {
    if (value.length === 0 || value.length > 4_096) {
      return;
    }
    const targetId = makeTargetId(kind, value);
    if (targets.length < MAX_NEW_TARGETS && !knownTargets.has(`${kind}:${value}`)) {
      knownTargets.add(`${kind}:${value}`);
      targets.push({
        id: targetId,
        kind,
        value,
        displayName: displayName(value),
        origin: "artifact",
      });
    }

    if (value.length > 2_048) {
      return;
    }
    const indicatorId = makeIndicatorId(kind, value);
    if (!knownIndicators.has(indicatorId)) {
      knownIndicators.add(indicatorId);
      indicators.push({
        id: indicatorId,
        kind,
        value,
        sourceAnalyzer: result.analyzer,
        sourcePass: result.pass,
        confidence: 0.5,
      });
    }
  };

  for (const url of extracted.urls) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        add("url", url);
      }
    } catch {
      // Skip malformed URLs.
    }
  }
  for (const ip of extracted.ips) {
    add("ip", ip);
  }
  for (const domain of extracted.domains) {
    if (!DOMAIN_NOISE.has(domain.toLowerCase())) {
      add("domain", domain);
    }
  }

  return { targets, indicators };
}
