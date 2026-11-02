import type { AdaptedAnalyzerResult } from "../types.js";
import type { SecFlowFinding } from "../../graph/schema/analyzer.js";
import { severityRiskScore } from "../../graph/schema/analyzer.js";
import {
  asArray,
  asBoolean,
  asNumber,
  asRecord,
  asString,
  joinRaw,
  jsonDumps,
  scalarText,
  truncate,
} from "../parse.js";

function adaptStatus(dataValue: unknown): SecFlowFinding[] {
  const data = asRecord(dataValue);
  if (data.isUp === false) {
    return [
      {
        type: "host_down",
        detail: `Target is DOWN (status: ${scalarText(data.responseCode, "?")})`,
        severity: "medium",
        evidence: truncate(jsonDumps(data), 300),
      },
    ];
  }
  return [];
}

function adaptSecurityHeaders(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const findings: SecFlowFinding[] = [];
  const missing = asArray(data.missing)
    .map((value) => asString(value))
    .filter(Boolean);
  const present = asArray(data.present)
    .map((value) => asString(value))
    .filter(Boolean);
  const score = data.score ?? "?";
  const raw = `security-headers: score=${scalarText(score)}, missing=${missing.join(", ")}`;

  for (const header of missing) {
    const severity: SecFlowFinding["severity"] =
      header === "Content-Security-Policy" || header === "Strict-Transport-Security"
        ? "high"
        : "medium";
    findings.push({
      type: "missing_security_header",
      detail: `Missing security header: ${header}`,
      severity,
      evidence: header,
    });
  }

  findings.push({
    type: "security_headers_summary",
    detail: `Security headers score: ${scalarText(score)} — ${missing.length} missing, ${present.length} present`,
    severity: "info",
    evidence: present.slice(0, 5).join(", ") || "none",
  });
  return { findings, raw };
}

function adaptSsl(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  if ("error" in data || data.success === false) {
    return {
      findings: [],
      raw: `ssl: error=${asString(data.error, "unknown")}`,
    };
  }
  const subject = data.subject;
  const issuer = data.issuer;
  const notAfter = asString(data.notAfter);
  return {
    findings: [
      {
        type: "ssl_certificate",
        detail: `SSL cert: issuer=${jsonDumps(issuer)}, expires=${notAfter}`,
        severity: "info",
        evidence: truncate(jsonDumps(data), 400),
      },
    ],
    raw: `ssl: subject=${jsonDumps(subject)}, issuer=${jsonDumps(issuer)}, expires=${notAfter}`,
  };
}

function adaptTls(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const tlsVersion = asString(data.tlsVersion);
  const cipher =
    typeof data.cipher === "string"
      ? data.cipher
      : data.cipher === undefined
        ? ""
        : jsonDumps(data.cipher);
  const raw = `tls: version=${tlsVersion}, cipher=${cipher}`;
  if (tlsVersion === "TLSv1" || tlsVersion === "TLSv1.1") {
    return {
      findings: [
        {
          type: "tls_weakness",
          detail: `Deprecated TLS version in use: ${tlsVersion}`,
          severity: "high",
          evidence: raw,
        },
      ],
      raw,
    };
  }
  if (tlsVersion) {
    return {
      findings: [
        {
          type: "tls_info",
          detail: `TLS: ${tlsVersion}, cipher: ${cipher}`,
          severity: "info",
          evidence: raw,
        },
      ],
      raw,
    };
  }
  return { findings: [], raw };
}

function adaptHsts(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const present = asBoolean(data.present);
  const raw = `hsts: present=${present}`;
  return {
    findings: present
      ? []
      : [
          {
            type: "missing_hsts",
            detail: "HSTS policy is not configured",
            severity: "medium",
            evidence: truncate(jsonDumps(data), 200),
          },
        ],
    raw,
  };
}

function adaptFirewall(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const hasWaf = asBoolean(data.hasWaf);
  const wafName = asString(data.waf);
  const raw = `firewall: hasWAF=${hasWaf}, waf=${wafName}`;
  return {
    findings: [
      {
        type: "waf_detection",
        detail: hasWaf ? `WAF detected: ${wafName}` : "No WAF detected",
        severity: hasWaf ? "info" : "low",
        evidence: raw,
      },
    ],
    raw,
  };
}

function adaptRedirects(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const redirects = asArray(data.redirects);
  const raw = `redirects: count=${redirects.length}`;
  return {
    findings:
      redirects.length > 3
        ? [
            {
              type: "excessive_redirects",
              detail: `Unusual redirect chain (${redirects.length} hops)`,
              severity: "low",
              evidence: truncate(jsonDumps(redirects), 400),
            },
          ]
        : [],
    raw,
  };
}

function adaptRedirectChain(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const riskAssessment = asRecord(data.risk_assessment);
  const riskLevel = asString(riskAssessment.risk_level, "low");
  const totalHops = asNumber(data.total_hops);
  const isSafe = asBoolean(data.is_safe, true);
  const raw = `redirect_chain: hops=${totalHops}, risk=${riskLevel}, safe=${isSafe}`;

  const severityMap: Record<string, SecFlowFinding["severity"]> = {
    high: "high",
    medium: "medium",
    low: "info",
  };
  const severity = severityMap[riskLevel.toLowerCase()] ?? "info";
  return {
    findings:
      !isSafe || riskLevel === "high" || riskLevel === "medium"
        ? [
            {
              type: "redirect_chain_risk",
              detail: `Redirect chain (${totalHops} hops) — risk level: ${riskLevel}`,
              severity,
              evidence: truncate(jsonDumps(riskAssessment), 400),
            },
          ]
        : [],
    raw,
  };
}

function adaptMalwareCheck(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const isMalicious = asBoolean(data.is_malicious);
  const riskLevel = asString(data.risk_level, "low");
  const detections = asArray(data.detections);
  const detectionCount = asNumber(data.detection_count);
  const raw = `malware_check: malicious=${isMalicious}, detections=${detectionCount}, risk=${riskLevel}`;

  return {
    findings: [
      isMalicious
        ? {
            type: "url_malicious",
            detail: `URL flagged as malicious by ${detectionCount} source(s) — risk: ${riskLevel}`,
            severity: riskLevel === "high" ? "critical" : "high",
            evidence: truncate(jsonDumps(detections), 400),
          }
        : {
            type: "url_clean",
            detail: "URL not found in malware/phishing databases",
            severity: "info",
            evidence: raw,
          },
    ],
    raw,
  };
}

function adaptUrlParse(dataValue: unknown): { findings: SecFlowFinding[]; raw: string } {
  const data = asRecord(dataValue);
  const isValid = asBoolean(data.is_valid, true);
  const suspiciousIndicators = asArray(data.suspicious_indicators);
  const riskLevel = asString(data.risk_level, "low");
  const raw = `url_parse: valid=${isValid}, suspicious_indicators=${suspiciousIndicators.length}, risk=${riskLevel}`;
  return {
    findings: suspiciousIndicators.map((indicator) => ({
      type: "url_suspicious_indicator",
      detail: `URL suspicious indicator: ${String(indicator)}`,
      severity: riskLevel === "high" ? "high" : "medium",
      evidence: String(indicator),
    })),
    raw,
  };
}

type Adapter = (value: unknown) => { findings: SecFlowFinding[]; raw: string };

const ADAPTERS: Record<string, Adapter> = {
  security_headers: adaptSecurityHeaders,
  ssl: adaptSsl,
  tls: adaptTls,
  hsts: adaptHsts,
  firewall: adaptFirewall,
  redirects: adaptRedirects,
  redirect_chain: adaptRedirectChain,
  malware_check: adaptMalwareCheck,
  url_parse: adaptUrlParse,
};

/**
 * Translate aggregated web-analyzer endpoint responses into the SecFlow
 * contract. Mirrors backend/orchestrator/app/adapters/web_adapter.py.
 */
export function adaptWeb(aggregated: unknown, inputDisplayName: string): AdaptedAnalyzerResult {
  const record = asRecord(aggregated);
  const findings: SecFlowFinding[] = [];
  const rawParts: string[] = [`Web analysis for: ${inputDisplayName}`];

  if ("status" in record) {
    findings.push(...adaptStatus(record.status));
    rawParts.push(`status: up=${String(asRecord(record.status).isUp)}`);
  }

  for (const [key, adapter] of Object.entries(ADAPTERS)) {
    if (!(key in record)) {
      continue;
    }
    const result = adapter(record[key]);
    findings.push(...result.findings);
    if (result.raw) {
      rawParts.push(result.raw);
    }
  }

  return {
    findings,
    riskScore: severityRiskScore(findings),
    rawOutput: joinRaw(rawParts),
  };
}
