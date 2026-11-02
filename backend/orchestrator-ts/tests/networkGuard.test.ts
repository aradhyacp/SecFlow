import { describe, expect, it } from "vitest";

import {
  createNetworkGuard,
  isObviouslyProhibitedTarget,
  prohibitedIpReason,
  SsrfBlockedError,
  type HostLookup,
} from "../src/security/networkGuard.js";

const publicLookup: HostLookup = async () => [{ address: "93.184.216.34", family: 4 }];
const privateLookup: HostLookup = async () => [{ address: "10.1.2.3", family: 4 }];

function target(kind: "url" | "ip" | "domain", value: string) {
  return { kind, value, displayName: value };
}

async function rejection(promise: Promise<void>): Promise<SsrfBlockedError> {
  return promise.then(
    () => {
      throw new Error("expected the target to be rejected");
    },
    (error: unknown) => {
      expect(error).toBeInstanceOf(SsrfBlockedError);
      return error as SsrfBlockedError;
    },
  );
}

describe("SSRF network guard", () => {
  const guard = createNetworkGuard({ allowPrivateTargets: false, lookup: publicLookup });

  it("blocks loopback, private, link-local and metadata destinations", async () => {
    const blocked = [
      target("url", "http://127.0.0.1/admin"),
      target("url", "http://localhost:5000/"),
      target("url", "http://[::1]/"),
      target("url", "http://169.254.169.254/latest/meta-data"),
      target("url", "http://10.0.0.5/"),
      target("url", "http://192.168.1.1/"),
      target("url", "http://[fd00::1]/"),
      target("url", "http://metadata.google.internal/"),
      target("url", "http://intranet/"),
      target("ip", "127.0.0.1"),
      target("ip", "100.64.0.1"),
      target("domain", "service.internal"),
    ];

    for (const candidate of blocked) {
      await rejection(guard.assertTargetAllowed(candidate));
    }
  });

  it("blocks a hostname that resolves into private space", async () => {
    const privateGuard = createNetworkGuard({
      allowPrivateTargets: false,
      lookup: privateLookup,
    });
    const error = await rejection(
      privateGuard.assertTargetAllowed(target("url", "https://looks-public.example/path")),
    );
    expect(error.message).toContain("resolves to 10.1.2.3");
  });

  it("blocks if any resolved address is private", async () => {
    const mixedGuard = createNetworkGuard({
      allowPrivateTargets: false,
      lookup: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "192.168.1.10", family: 4 },
      ],
    });
    await rejection(mixedGuard.assertTargetAllowed(target("domain", "mixed.example")));
  });

  it("allows public IP and hostname targets", async () => {
    await expect(guard.assertTargetAllowed(target("ip", "8.8.8.8"))).resolves.toBeUndefined();
    await expect(
      guard.assertTargetAllowed(target("url", "https://example.com/report")),
    ).resolves.toBeUndefined();
    await expect(
      guard.assertTargetAllowed(target("domain", "example.com")),
    ).resolves.toBeUndefined();
  });

  it("rejects URL credentials, non-HTTP schemes and malformed URLs", async () => {
    for (const value of [
      "https://user:password@example.com/",
      "file:///etc/passwd",
      "ftp://example.com/file",
      "not a url",
    ]) {
      await rejection(guard.assertTargetAllowed(target("url", value)));
    }
  });

  it("can be disabled for local demos", async () => {
    const localGuard = createNetworkGuard({
      allowPrivateTargets: true,
      lookup: privateLookup,
    });
    await expect(
      localGuard.assertTargetAllowed(target("url", "http://127.0.0.1:8080/")),
    ).resolves.toBeUndefined();
  });

  it("allows DNS failures by default but can fail closed", async () => {
    const failingLookup: HostLookup = async () => {
      throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
    };
    await expect(
      createNetworkGuard({
        allowPrivateTargets: false,
        lookup: failingLookup,
      }).assertTargetAllowed(target("domain", "unresolvable.example")),
    ).resolves.toBeUndefined();

    await rejection(
      createNetworkGuard({
        allowPrivateTargets: false,
        lookup: failingLookup,
        allowDnsFailure: false,
      }).assertTargetAllowed(target("domain", "unresolvable.example")),
    );
  });

  it("classifies common prohibited IP ranges without DNS", () => {
    expect(prohibitedIpReason("127.0.0.1")).toContain("loopback");
    expect(prohibitedIpReason("169.254.169.254")).toContain("metadata");
    expect(prohibitedIpReason("::1")).toContain("loopback");
    expect(prohibitedIpReason("::ffff:127.0.0.1")).toContain("prohibited IPv4");
    expect(prohibitedIpReason("::ffff:0:127.0.0.1")).toContain("prohibited IPv4");
    expect(prohibitedIpReason("168.63.129.16")).toContain("Azure");
    expect(prohibitedIpReason("::ffff:8.8.8.8")).toBeNull();
    expect(prohibitedIpReason("8.8.8.8")).toBeNull();
  });

  it("filters obvious artifact targets synchronously", () => {
    expect(isObviouslyProhibitedTarget("url", "http://127.0.0.1/payload")).toBe(true);
    expect(isObviouslyProhibitedTarget("url", "https://example.com/payload")).toBe(false);
    expect(isObviouslyProhibitedTarget("domain", "localhost")).toBe(true);
    expect(isObviouslyProhibitedTarget("ip", "8.8.8.8")).toBe(false);
  });
});
