import type { AdaptedAnalyzerResult } from "../types.js";
import type { SecFlowFinding } from "../../graph/schema/analyzer.js";
import {
  asBoolean,
  asNumber,
  asRecord,
  asRecordArray,
  asString,
  joinRaw,
  jsonDumps,
} from "../parse.js";

const RISK_SCORE: Record<string, number> = {
  malicious: 9.5,
  suspicious: 6.5,
  macro_present: 3.0,
  clean: 0.5,
};

const INDICATOR_SEVERITY: Record<string, SecFlowFinding["severity"]> = {
  AutoExec: "critical",
  Suspicious: "high",
  IOC: "high",
  "Hex String": "medium",
  "Base64 String": "medium",
  "Dridex String": "critical",
  "VBA String": "low",
};

/**
 * Translate a macro-analyzer /analyze response into the SecFlow contract.
 * Ports the retired Python macro adapter.
 */
export function adaptMacro(rawValue: unknown, inputDisplayName = "unknown"): AdaptedAnalyzerResult {
  const raw = asRecord(rawValue);
  const findings: SecFlowFinding[] = [];
  const rawParts: string[] = [];

  const riskLevel = asString(raw.risk_level, "clean");
  const hasMacros = asBoolean(raw.has_macros);
  const macroCount = asNumber(raw.macro_count);
  const fileType = asString(raw.file_type, "unknown");
  const filename = asString(raw.filename, inputDisplayName);
  const flags = asRecord(raw.flags);
  const indicators = asRecord(raw.indicators);
  const iocs = asRecordArray(raw.iocs);
  const macros = asRecordArray(raw.macros);
  const xlmMacros = raw.xlm_macros;

  if (hasMacros) {
    const severity: SecFlowFinding["severity"] =
      riskLevel === "malicious" ? "critical" : riskLevel === "suspicious" ? "high" : "medium";
    const activeFlags = Object.entries(flags)
      .filter(([, value]) => asBoolean(value))
      .map(([key]) => key);
    findings.push({
      type: `macro_${riskLevel}`,
      detail: `${macroCount} VBA macro module(s) found in ${filename} (${fileType}). Flags: ${
        activeFlags.length > 0 ? activeFlags.join(", ") : "none"
      }.`,
      severity,
      evidence: jsonDumps(flags),
    });
    rawParts.push(
      `VBA macros: ${macroCount} module(s), risk=${riskLevel}, flags=[${activeFlags.join(", ")}]`,
    );
  } else {
    findings.push({
      type: "macro_clean",
      detail: `No VBA macros detected in ${filename} (${fileType}).`,
      severity: "info",
      evidence: "",
    });
    rawParts.push(`No macros in ${filename}`);
  }

  for (const [category, rawItems] of Object.entries(indicators)) {
    const items = asRecordArray(rawItems);
    if (items.length === 0) {
      continue;
    }
    let severity = INDICATOR_SEVERITY[category] ?? "low";
    if (category === "AutoExec" && asBoolean(flags.suspicious)) {
      severity = "critical";
    }

    const keywords = items.map((item) => asString(item.keyword));
    const summary = keywords.slice(0, 10).join(", ");
    const overflow = items.length > 10 ? ` … (+${items.length - 10} more)` : "";
    findings.push({
      type: `macro_indicator_${category.toLowerCase().replaceAll(" ", "_")}`,
      detail: `${category}: ${summary}${overflow}`,
      severity,
      evidence: jsonDumps(items),
    });
    rawParts.push(`  [${category}] ${summary}`);
  }

  if (iocs.length > 0) {
    const iocValues = iocs.map((ioc) => asString(ioc.value));
    const summary = iocValues.slice(0, 5).join(", ");
    const overflow = iocValues.length > 5 ? ` … (+${iocValues.length - 5} more)` : "";
    findings.push({
      type: "macro_ioc",
      detail: `IOCs extracted from macros: ${summary}${overflow}`,
      severity: "high",
      evidence: jsonDumps(iocValues),
    });
    rawParts.push("IOCs:");
    rawParts.push(...iocValues.map((value) => `  ${value}`));
  }

  if (macros.length > 0) {
    const codeSections = macros.map(
      (macro) =>
        `--- Module: ${asString(macro.module, "?")} (stream: ${asString(macro.stream, "?")}) ---\n${asString(macro.code)}`,
    );
    const fullCode = codeSections.join("\n\n");
    findings.push({
      type: "macro_source",
      detail: `Full VBA source across ${macros.length} module(s)`,
      severity: "info",
      evidence: fullCode,
    });
    rawParts.push(fullCode);
  }

  if (xlmMacros) {
    const evidence = typeof xlmMacros === "string" ? xlmMacros : jsonDumps(xlmMacros);
    findings.push({
      type: "macro_xlm",
      detail: "Excel 4 (XLM) macros detected and deobfuscated",
      severity: "high",
      evidence,
    });
    rawParts.push(`XLM macros: ${evidence.slice(0, 200)}`);
  }

  const vt = asRecord(raw.vt);
  if (Object.keys(vt).length > 0) {
    if (vt.success !== true) {
      const vtError = asString(vt.error, "VT scan failed");
      findings.push({
        type: "error",
        detail: `VirusTotal: ${vtError}`,
        severity: "low",
        evidence: "",
      });
      rawParts.push(`VT error: ${vtError}`);
    } else {
      const stats = asRecord(vt.stats);
      const resultsMap = asRecord(vt.results);
      const malicious = asNumber(stats.malicious);
      const suspicious = asNumber(stats.suspicious);
      const total = Object.values(stats).reduce<number>((sum, value) => sum + asNumber(value), 0);
      rawParts.push(`VT: malicious=${malicious}, suspicious=${suspicious}, total=${total}`);
      if (malicious > 0 || suspicious > 0) {
        const severity: SecFlowFinding["severity"] =
          malicious >= 5 ? "critical" : malicious > 0 ? "high" : "medium";
        findings.push({
          type: "malware_detection",
          detail: `VirusTotal: ${malicious} malicious, ${suspicious} suspicious out of ${total} engines`,
          severity,
          evidence: jsonDumps(stats),
        });
        for (const [engine, rawResult] of Object.entries(resultsMap).slice(0, 10)) {
          const result = asRecord(rawResult);
          if (result.category === "malicious" || result.category === "suspicious") {
            findings.push({
              type: "av_detection",
              detail: `${engine}: ${asString(result.result, "detected")}`,
              severity: result.category === "malicious" ? "high" : "medium",
              evidence: jsonDumps(result),
            });
            rawParts.push(`  [${engine}] ${asString(result.result)}`);
          }
        }
      } else {
        findings.push({
          type: "malware_detection",
          detail: `VirusTotal: no detections (${total} engines clean)`,
          severity: "info",
          evidence: jsonDumps(stats),
        });
      }
    }
  }

  let riskScore = RISK_SCORE[riskLevel] ?? 0;
  if (vt.success === true) {
    const malicious = asNumber(asRecord(vt.stats).malicious);
    if (malicious >= 5) {
      riskScore = Math.max(riskScore, 9.5);
    } else if (malicious > 0) {
      riskScore = Math.max(riskScore, 7.0);
    }
  }

  return {
    findings,
    riskScore: Math.round(riskScore * 100) / 100,
    rawOutput: joinRaw(rawParts),
  };
}
