import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { adaptMacro } from "../src/analyzers/adapters/macro.js";
import { adaptMalware } from "../src/analyzers/adapters/malware.js";
import { adaptRecon } from "../src/analyzers/adapters/recon.js";
import { adaptSteg } from "../src/analyzers/adapters/steg.js";
import { adaptWeb } from "../src/analyzers/adapters/web.js";
import { secFlowResultSchema } from "../src/graph/schema/analyzer.js";

const FIXTURES_DIR = new URL("../../../docs/ts-migration/fixtures/", import.meta.url);

function fixture<T>(name: string): T {
  return JSON.parse(readFileSync(fileURLToPath(new URL(name, FIXTURES_DIR)), "utf8")) as T;
}

function asContract(
  analyzer: "malware" | "steg" | "recon" | "web" | "macro",
  adapted: ReturnType<typeof adaptMalware>,
) {
  return secFlowResultSchema.parse({
    analyzer,
    pass: 1,
    input: "fixture",
    findings: adapted.findings,
    risk_score: adapted.riskScore,
    raw_output: adapted.rawOutput,
    ...(adapted.extractedFiles ? { extracted_files: adapted.extractedFiles } : {}),
  });
}

describe("malware adapter", () => {
  it("matches the recorded VirusTotal + Ghidra contract", () => {
    const adapted = adaptMalware({
      vt: fixture("malware-file-analysis.json"),
      decompile: fixture("malware-decompile.json"),
    });

    const contract = asContract("malware", adapted);
    expect(contract.risk_score).toBe(10);
    expect(contract.findings.map((finding) => finding.type)).toEqual([
      "malware_detection",
      "av_detection",
      "av_detection",
      "av_detection",
      "av_detection",
      "av_detection",
      "av_detection",
      "av_detection",
      "av_detection",
      "decompilation",
      "disassembly",
    ]);
    expect(contract.findings[0]?.detail).toContain("7 malicious");
  });

  it("returns a clean result for an undetected binary", () => {
    const adapted = adaptMalware({
      vt: fixture("malware-file-analysis-clean.json"),
      decompile: fixture("malware-decompile.json"),
    });
    expect(adapted.riskScore).toBe(0);
    expect(adapted.findings[0]).toMatchObject({
      type: "malware_detection",
      severity: "info",
    });
  });

  it("turns both upstream failures into low-severity error findings", () => {
    const adapted = adaptMalware({
      vt: { success: false, error: "VT unavailable" },
      decompile: { success: false, error: "Ghidra unavailable" },
    });
    expect(adapted.findings).toHaveLength(2);
    expect(adapted.findings.every((finding) => finding.severity === "low")).toBe(true);
    expect(adapted.riskScore).toBe(0.6);
  });
});

describe("steg adapter", () => {
  it("matches the recorded results payload", () => {
    const adapted = adaptSteg(fixture("steg-result.json"));
    const contract = asContract("steg", adapted);

    expect(contract.risk_score).toBe(5);
    expect(contract.extracted_files).toEqual(["/download/abc123/binwalk/embedded.zip"]);
    expect(contract.findings.map((finding) => finding.type)).toEqual([
      "steg_detection",
      "steg_detection",
      "steg_info",
    ]);
  });

  it("returns an empty successful result for an empty payload", () => {
    expect(adaptSteg({})).toMatchObject({ findings: [], riskScore: 0, extractedFiles: [] });
  });
});

describe("recon adapter", () => {
  it("matches the recorded /scan response", () => {
    const adapted = adaptRecon(fixture("recon-scan.json"), "8.8.8.8");
    const contract = asContract("recon", adapted);

    expect(contract.risk_score).toBe(4);
    expect(contract.findings.map((finding) => finding.type)).toEqual([
      "geolocation",
      "blocklist_check",
      "ioc_match",
    ]);
  });

  it("matches the recorded /footprint email response", () => {
    const adapted = adaptRecon(fixture("recon-footprint-email.json"), "user@example.com");
    expect(adapted.findings[0]).toMatchObject({ type: "email_breach", severity: "critical" });
    expect(adapted.riskScore).toBe(4);
  });

  it("returns an empty result for an empty response", () => {
    const adapted = adaptRecon({}, "8.8.8.8");
    expect(adapted.findings).toEqual([]);
    expect(adapted.riskScore).toBe(0);
    expect(adapted.rawOutput).toContain("Recon analysis for: 8.8.8.8");
  });
});

describe("web adapter", () => {
  it("matches the recorded aggregated endpoint responses", () => {
    const adapted = adaptWeb(fixture("web-aggregated.json"), "https://example.com");
    const contract = asContract("web", adapted);

    expect(contract.risk_score).toBe(9.8);
    expect(
      contract.findings.filter((finding) => finding.type === "missing_security_header"),
    ).toHaveLength(7);
    expect(contract.findings.find((finding) => finding.type === "tls_info")?.detail).toContain(
      "TLSv1.3",
    );
  });

  it("returns an empty result when every endpoint failed", () => {
    const adapted = adaptWeb({}, "https://example.com");
    expect(adapted.findings).toEqual([]);
    expect(adapted.rawOutput).toContain("Web analysis for: https://example.com");
  });
});

describe("macro adapter", () => {
  it("matches the recorded macro verdict", () => {
    const adapted = adaptMacro(fixture("macro-analyze.json"), "sample.docm");
    const contract = asContract("macro", adapted);

    expect(contract.risk_score).toBe(9.5);
    expect(contract.findings[0]).toMatchObject({
      type: "macro_malicious",
      severity: "critical",
    });
    expect(contract.findings.some((finding) => finding.type === "macro_source")).toBe(true);
  });

  it("keeps the Python behaviour of a 0.5 risk result on total failure", () => {
    const adapted = adaptMacro({ success: false, error: "offline" }, "sample.docm");
    expect(adapted.riskScore).toBe(0.5);
    expect(adapted.findings[0]?.type).toBe("macro_clean");
  });
});
