import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import type { AnalysisTarget, TargetKind } from "../graph/state.js";

/** A target the orchestrator refuses to send to a network-capable analyzer. */
export class SsrfBlockedError extends Error {
  readonly code = "prohibited_target";

  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

export interface ResolvedAddress {
  address: string;
  family: number;
}

export type HostLookup = (hostname: string) => Promise<readonly ResolvedAddress[]>;

export interface NetworkGuard {
  assertTargetAllowed(
    target: Pick<AnalysisTarget, "kind" | "value" | "displayName">,
  ): Promise<void>;
}

export interface NetworkGuardOptions {
  /** Local demos intentionally analyze loopback/private targets. */
  allowPrivateTargets: boolean;
  /** Injectable for deterministic tests and offline environments. */
  lookup?: HostLookup;
  /** DNS failures are allowed by default; an unresolvable name cannot reach a private address. */
  allowDnsFailure?: boolean;
}

const BLOCKED_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".lan"] as const;

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
  "instance-data",
]);

const defaultLookup: HostLookup = async (hostname) => {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map((entry) => ({ address: entry.address, family: entry.family }));
};

function normalizeHostname(value: string): string {
  let hostname = value.trim().toLowerCase();
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }
  return hostname.replace(/\.+$/, "");
}

function blockedHostnameReason(hostname: string): string | null {
  if (BLOCKED_HOSTNAMES.has(hostname)) {
    return "it is an internal or metadata-service hostname";
  }
  if (!hostname.includes(".") && isIP(hostname) === 0) {
    return "it is a single-label internal hostname";
  }
  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (hostname.endsWith(suffix)) {
      return `it uses the internal name suffix ${suffix}`;
    }
  }
  if (hostname.includes("%")) {
    return "it contains an IPv6 zone identifier";
  }
  return null;
}

function blockedIpv4Reason(address: string): string | null {
  const parts = address.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return "it is not a valid IPv4 address";
  }
  const [a = 0, b = 0, c = 0] = parts;

  if (a === 0) return "it is in the unspecified IPv4 range";
  if (a === 10) return "it is a private IPv4 address";
  if (a === 127) return "it is an IPv4 loopback address";
  if (a === 100 && b >= 64 && b <= 127) return "it is in the carrier-grade NAT range";
  if (a === 169 && b === 254) return "it is a link-local or cloud metadata address";
  if (address === "168.63.129.16") return "it is an Azure platform/metadata address";
  if (a === 172 && b >= 16 && b <= 31) return "it is a private IPv4 address";
  if (a === 192 && b === 168) return "it is a private IPv4 address";
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return "it is a reserved IPv4 address";
  if (a === 192 && b === 88 && c === 99) return "it is a reserved IPv4 address";
  if (a === 198 && (b === 18 || b === 19)) return "it is in the benchmarking range";
  if (a === 198 && b === 51 && c === 100) return "it is a documentation address";
  if (a === 203 && b === 0 && c === 113) return "it is a documentation address";
  if (a >= 224) return "it is multicast or reserved IPv4 space";
  return null;
}

function parseIpv6Groups(address: string): number[] | null {
  const normalized = address.toLowerCase().split("%")[0] ?? "";
  const compressed = normalized.includes("::");
  const [head = "", tail = "", extra] = normalized.split("::");
  if (extra !== undefined) {
    return null;
  }

  function parseSide(side: string): number[] | null {
    if (side.length === 0) {
      return [];
    }
    const groups: number[] = [];
    for (const part of side.split(":")) {
      if (part.length === 0) {
        return null;
      }
      if (part.includes(".")) {
        if (isIP(part) !== 4) {
          return null;
        }
        const octets = part.split(".").map((octet) => Number(octet));
        if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) {
          return null;
        }
        const [a = 0, b = 0, c = 0, d = 0] = octets;
        groups.push((a << 8) | b, (c << 8) | d);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(part)) {
          return null;
        }
        groups.push(Number.parseInt(part, 16));
      }
    }
    return groups;
  }

  const headGroups = parseSide(head);
  const tailGroups = parseSide(tail);
  if (!headGroups || !tailGroups) {
    return null;
  }

  if (!compressed) {
    return headGroups.length === 8 ? headGroups : null;
  }

  const zeros = 8 - headGroups.length - tailGroups.length;
  if (zeros < 1) {
    return null;
  }
  return [...headGroups, ...Array<number>(zeros).fill(0), ...tailGroups];
}

function embeddedIpv4(words: readonly number[]): string | null {
  if (words.length !== 8) {
    return null;
  }
  const high = words[6] ?? 0;
  const low = words[7] ?? 0;
  return `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;
}

function blockedIpv6Reason(address: string): string | null {
  const normalized = address.toLowerCase().split("%")[0] ?? "";
  const words = parseIpv6Groups(normalized);
  if (!words) {
    return "it is not a valid IPv6 address";
  }
  const first = words[0] ?? 0;

  if (words.every((word) => word === 0)) {
    return "it is the IPv6 unspecified address";
  }
  if (words.slice(0, 7).every((word) => word === 0) && words[7] === 1) {
    return "it is an IPv6 loopback address";
  }

  // IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible `::a.b.c.d`, and the
  // deprecated IPv4-translated `::ffff:0:a.b.c.d` form.
  const mappedPrefix =
    words.slice(0, 5).every((word) => word === 0) && (words[5] === 0 || words[5] === 0xffff);
  const translatedPrefix =
    words.slice(0, 4).every((word) => word === 0) && words[4] === 0xffff && words[5] === 0;
  if (mappedPrefix || translatedPrefix) {
    const mapped = embeddedIpv4(words);
    if (mapped) {
      const reason = blockedIpv4Reason(mapped);
      if (reason) {
        return `it embeds a prohibited IPv4 address (${reason})`;
      }
    }
  }

  // 6to4 carries an IPv4 address in the second and third groups.
  if (first === 0x2002) {
    const embedded = `${words[1]! >> 8}.${words[1]! & 0xff}.${words[2]! >> 8}.${words[2]! & 0xff}`;
    const reason = blockedIpv4Reason(embedded);
    if (reason) {
      return `it embeds a prohibited IPv4 address (${reason})`;
    }
  }

  if ((first & 0xfe00) === 0xfc00) return "it is a unique-local IPv6 address";
  if ((first & 0xffc0) === 0xfe80) return "it is an IPv6 link-local address";
  if ((first & 0xff00) === 0xff00) return "it is an IPv6 multicast address";
  if (first === 0x2001 && words[1] === 0x0db8) return "it is an IPv6 documentation address";
  if (first === 0x2001 && words[1] === 0x0000) return "it is a Teredo transition address";
  if (first === 0x2001 && words[1] === 0x0002) return "it is an IPv6 benchmarking address";
  if (first === 0x0064 && words[1] === 0xff9b) return "it is a NAT64 transition address";

  return null;
}

/** Exposed for fast, DNS-free filtering and unit tests. */
export function prohibitedIpReason(address: string): string | null {
  const family = isIP(address);
  if (family === 4) {
    return blockedIpv4Reason(address);
  }
  if (family === 6) {
    return blockedIpv6Reason(address);
  }
  return "it is not a valid IP address";
}

/** Synchronous obvious check used when constructing artifact targets. */
export function isObviouslyProhibitedTarget(kind: TargetKind, value: string): boolean {
  if (kind === "ip") {
    return prohibitedIpReason(value) !== null;
  }
  if (kind === "domain") {
    return blockedHostnameReason(normalizeHostname(value)) !== null;
  }
  if (kind === "url") {
    try {
      const parsed = new URL(value);
      const hostname = normalizeHostname(parsed.hostname);
      return (
        blockedHostnameReason(hostname) !== null ||
        (isIP(hostname) !== 0 && prohibitedIpReason(hostname) !== null)
      );
    } catch {
      return true;
    }
  }
  return false;
}

function assertUrlShape(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new SsrfBlockedError("Prohibited network target: the URL is malformed.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SsrfBlockedError(
      "Prohibited network target: only HTTP and HTTPS URLs can be analyzed.",
    );
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new SsrfBlockedError(
      "Prohibited network target: URLs with embedded credentials are not allowed.",
    );
  }
  if (!parsed.hostname) {
    throw new SsrfBlockedError("Prohibited network target: the URL has no hostname.");
  }
  return parsed;
}

/**
 * Enforces SSRF boundaries before a target reaches web/recon analyzers.
 *
 * IP literals are checked directly. Hostnames are resolved first, and every
 * resolved address is checked so a public name pointing at loopback, private,
 * link-local, metadata or reserved space is still rejected. DNS failures are
 * allowed by default because an unresolvable destination cannot be reached;
 * callers can opt into fail-closed behavior.
 */
export function createNetworkGuard(options: NetworkGuardOptions): NetworkGuard {
  const resolve = options.lookup ?? defaultLookup;
  const allowDnsFailure = options.allowDnsFailure ?? true;

  async function assertHostnameAllowed(hostname: string): Promise<void> {
    const host = normalizeHostname(hostname);
    if (host.length === 0) {
      throw new SsrfBlockedError("Prohibited network target: the hostname is empty.");
    }
    const hostReason = blockedHostnameReason(host);
    if (hostReason) {
      throw new SsrfBlockedError(`Prohibited network target: ${hostReason}.`);
    }

    if (isIP(host) !== 0) {
      const ipReason = prohibitedIpReason(host);
      if (ipReason) {
        throw new SsrfBlockedError(`Prohibited network target: ${ipReason}.`);
      }
      return;
    }

    let addresses: readonly ResolvedAddress[];
    try {
      addresses = await resolve(host);
    } catch (error) {
      if (allowDnsFailure) {
        return;
      }
      throw new SsrfBlockedError(
        `Prohibited network target: DNS resolution failed for ${host} (${
          error instanceof Error ? error.message : String(error)
        }).`,
      );
    }

    for (const entry of addresses) {
      const ipReason = prohibitedIpReason(entry.address);
      if (ipReason) {
        throw new SsrfBlockedError(
          `Prohibited network target: ${host} resolves to ${entry.address}, and ${ipReason}.`,
        );
      }
    }
  }

  return {
    async assertTargetAllowed(target) {
      switch (target.kind) {
        case "url": {
          // Even local demos must use an HTTP(S) URL without credentials.
          const parsed = assertUrlShape(target.value);
          if (!options.allowPrivateTargets) {
            await assertHostnameAllowed(parsed.hostname);
          }
          return;
        }
        case "ip":
        case "domain":
          if (!options.allowPrivateTargets) {
            await assertHostnameAllowed(target.value);
          }
          return;
        default:
          // File, email, phone and username targets are not fetched by the
          // orchestrator; recon sends them as query strings to its own API.
          return;
      }
    },
  };
}
