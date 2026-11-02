import type { AdaptedAnalyzerResult } from "../types.js";
import type { SecFlowFinding } from "../../graph/schema/analyzer.js";
import { severityRiskScore } from "../../graph/schema/analyzer.js";
import {
  asArray,
  asBoolean,
  asNumber,
  asRecord,
  asRecordArray,
  asString,
  joinRaw,
  jsonDumps,
  scalarText,
  truncate,
} from "../parse.js";

interface RawParts {
  findings: SecFlowFinding[];
  rawParts: string[];
}

function adaptVirustotal(vtValue: unknown, query: string, out: RawParts): void {
  const vt = asRecord(vtValue);
  if (vt.found !== true) {
    out.rawParts.push(`virustotal: not available (${asString(vt.error, "unknown error")})`);
    return;
  }

  const vtType = asString(vt.type, "unknown");
  const malicious = asNumber(vt.malicious);
  const suspicious = asNumber(vt.suspicious);
  const harmless = asNumber(vt.harmless);
  const undetected = asNumber(vt.undetected);
  const total = asNumber(vt.total);
  const reputation = asNumber(vt.reputation);
  const engines = asRecordArray(vt.engines);
  const link = asString(vt.link);

  out.rawParts.push(
    `virustotal (${vtType}): malicious=${malicious}, suspicious=${suspicious}, harmless=${harmless}, undetected=${undetected}, total=${total}, reputation=${reputation}`,
  );
  if (engines.length > 0) {
    out.rawParts.push(
      `  detections: ${engines
        .slice(0, 5)
        .map((engine) => `${asString(engine.engine)}=${asString(engine.result)}`)
        .join(", ")}`,
    );
  }

  let severity: SecFlowFinding["severity"];
  if (malicious >= 10) {
    severity = "critical";
  } else if (malicious >= 3 || (malicious > 0 && suspicious >= 3)) {
    severity = "high";
  } else if (malicious > 0 || suspicious >= 5) {
    severity = "medium";
  } else if (suspicious > 0) {
    severity = "low";
  } else {
    severity = "info";
  }

  const flagPct = total ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  let detail = `VirusTotal (${vtType.toUpperCase()}): ${malicious} malicious, ${suspicious} suspicious out of ${total} engines (${flagPct}% flagged)`;
  if (reputation < -10) {
    detail += ` — reputation score: ${reputation}`;
  }

  out.findings.push({
    type: "virustotal_scan",
    detail,
    severity,
    evidence: jsonDumps({
      found: true,
      type: vtType,
      query,
      malicious,
      suspicious,
      harmless,
      undetected,
      total,
      reputation,
      stats: vt.stats ?? {},
      engines,
      country: asString(vt.country),
      as_owner: asString(vt.as_owner),
      asn: vt.asn ?? null,
      network: asString(vt.network),
      registrar: asString(vt.registrar),
      categories: vt.categories ?? {},
      creation_date: vt.creation_date ?? null,
      final_url: asString(vt.final_url),
      link,
    }),
  });
}

function adaptScan(rawValue: unknown): RawParts {
  const raw = asRecord(rawValue);
  const findings: SecFlowFinding[] = [];
  const rawParts: string[] = [];
  const query = asString(raw.query, "unknown");

  const ipInfo = asRecordArray(asRecord(raw.ipapi).ip_info);
  if (ipInfo.length > 0) {
    const entry = ipInfo[0] as Record<string, unknown>;
    rawParts.push(`ipapi: ${truncate(jsonDumps(entry), 300)}`);
    findings.push({
      type: "geolocation",
      detail: `IP geolocation: country=${asString(entry.country, "?")}, ISP=${asString(entry.isp, "?")}, AS=${asString(entry.as, "?")}`,
      severity: "info",
      evidence: truncate(jsonDumps(entry), 400),
    });
  }

  const talos = asRecord(raw.talos);
  if (Object.keys(talos).length > 0) {
    const blacklisted = asBoolean(talos.blacklisted);
    rawParts.push(`talos: blacklisted=${blacklisted}`);
    findings.push(
      blacklisted
        ? {
            type: "blocklist_hit",
            detail: `Cisco Talos blocklist: ${query} is BLACKLISTED`,
            severity: "critical",
            evidence: jsonDumps(talos),
          }
        : {
            type: "blocklist_check",
            detail: `Cisco Talos blocklist: ${query} is clean`,
            severity: "info",
            evidence: jsonDumps(talos),
          },
    );
  }

  const tor = asRecord(raw.tor);
  if (Object.keys(tor).length > 0) {
    const isTor = asBoolean(tor.is_tor_exit);
    rawParts.push(`tor: is_tor_exit=${isTor}`);
    if (isTor) {
      findings.push({
        type: "tor_exit_node",
        detail: `${query} is a known Tor exit node`,
        severity: "high",
        evidence: jsonDumps(tor),
      });
    }
  }

  const tranco = asRecord(raw.tranco);
  if (Object.keys(tranco).length > 0) {
    const found = asBoolean(tranco.found);
    const rank = tranco.rank;
    rawParts.push(`tranco: found=${found}, rank=${scalarText(rank)}`);
    if (found && rank) {
      findings.push({
        type: "domain_rank",
        detail: `Tranco rank: #${scalarText(rank)} (well-known domain)`,
        severity: "info",
        evidence: jsonDumps(tranco),
      });
    }
  }

  const threatfox = asRecord(raw.threatfox);
  if (Object.keys(threatfox).length > 0 && asBoolean(threatfox.found)) {
    const malware = asString(threatfox.malware, "unknown malware");
    const confidence = asNumber(threatfox.confidence_level);
    rawParts.push(`threatfox: malware=${malware}, confidence=${confidence}`);
    findings.push({
      type: "ioc_match",
      detail: `ThreatFox IOC match: ${malware} (confidence: ${confidence}%)`,
      severity: confidence >= 75 ? "critical" : "high",
      evidence: jsonDumps(threatfox),
    });
  }

  const vt = asRecord(raw.virustotal);
  if (Object.keys(vt).length > 0) {
    adaptVirustotal(vt, query, { findings, rawParts });
  }

  return { findings, rawParts };
}

function adaptFootprint(rawValue: unknown): RawParts {
  const raw = asRecord(rawValue);
  const findings: SecFlowFinding[] = [];
  const rawParts: string[] = [];
  const query = asString(raw.query, "unknown");
  const inputType = asString(raw.type, "unknown");

  rawParts.push(`footprint type: ${inputType}, query: ${query}`);

  if (inputType === "email") {
    const emailScan = asRecord(raw.email_scan);
    const exposed = asBoolean(emailScan.exposed);
    const breachCount = asNumber(emailScan.breach_count);
    const risk = asRecordArray(emailScan.risk);

    rawParts.push(`email: exposed=${exposed}, breaches=${breachCount}`);
    if (exposed) {
      const riskLabel = risk.length > 0 ? asString(risk[0]?.risk_label, "Unknown") : "Unknown";
      const severity: SecFlowFinding["severity"] = riskLabel.includes("Critical")
        ? "critical"
        : breachCount > 5
          ? "high"
          : "medium";
      findings.push({
        type: "email_breach",
        detail: `Email exposed in ${breachCount} breach(es) — risk: ${riskLabel}`,
        severity,
        evidence: truncate(jsonDumps(emailScan), 500),
      });
      for (const breach of asArray(emailScan.breaches).slice(0, 5)) {
        const entry = asRecord(breach);
        rawParts.push(`  breach: ${asString(entry.breach, "?")} (${asString(entry.domain, "?")})`);
      }
    } else {
      findings.push({
        type: "email_check",
        detail: `Email ${query} not found in breach databases`,
        severity: "info",
        evidence: truncate(jsonDumps(emailScan), 200),
      });
    }
    return { findings, rawParts };
  }

  if (inputType === "phone") {
    const phoneScan = asRecord(raw.phone_scan);
    const valid = asBoolean(phoneScan.valid);
    rawParts.push(`phone: valid=${valid}, carrier=${asString(phoneScan.carrier, "?")}`);
    if (valid) {
      findings.push({
        type: "phone_validation",
        detail: `Phone valid: ${asString(phoneScan.country_name, "?")}, carrier=${asString(phoneScan.carrier, "?")}, type=${asString(phoneScan.line_type, "?")}`,
        severity: "info",
        evidence: truncate(jsonDumps(phoneScan), 300),
      });
    }
    return { findings, rawParts };
  }

  if (inputType === "username") {
    const usernameScan = asRecordArray(raw.username_scan);
    const platformCount = usernameScan.length;
    rawParts.push(`username: found on ${platformCount} platforms`);
    if (platformCount > 0) {
      findings.push({
        type: "username_presence",
        detail: `Username '${query}' found on ${platformCount} platform(s)`,
        severity: platformCount > 5 ? "medium" : "low",
        evidence: truncate(jsonDumps(usernameScan.slice(0, 10)), 400),
      });
      for (const site of usernameScan.slice(0, 5)) {
        rawParts.push(`  ${asString(site.site, "?")}: ${asString(site.url, "?")}`);
      }
    }
    return { findings, rawParts };
  }

  return { findings, rawParts };
}

/**
 * Translate a recon-analyzer /scan or /footprint response into the SecFlow
 * contract. Ports the retired Python recon adapter.
 */
export function adaptRecon(raw: unknown, inputDisplayName: string): AdaptedAnalyzerResult {
  const record = asRecord(raw);
  const findings: SecFlowFinding[] = [];
  const rawParts: string[] = [`Recon analysis for: ${inputDisplayName}`];

  let adapted: RawParts;
  if ("ipapi" in record || "talos" in record || "tor" in record) {
    adapted = adaptScan(record);
  } else if (["email", "phone", "username"].includes(asString(record.type))) {
    adapted = adaptFootprint(record);
  } else {
    const fallback = truncate(jsonDumps(record), 1000);
    rawParts.push(fallback);
    adapted = { findings: [], rawParts: [fallback] };
  }

  findings.push(...adapted.findings);
  rawParts.push(...adapted.rawParts);

  return {
    findings,
    riskScore: severityRiskScore(findings),
    rawOutput: joinRaw(rawParts),
  };
}
