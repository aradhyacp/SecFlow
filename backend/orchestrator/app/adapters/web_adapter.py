"""
Web Adapter — aggregates responses from multiple Web-Analyzer GET endpoints
into the SecFlow contract.

Web-Analyzer exposes individual GET endpoints with ?url= param.
The orchestrator calls the most security-relevant ones and this adapter
normalizes the aggregated result.

Called by the orchestrator after _call_web_analyzer() which returns:
  {
      "security_headers": {...},
      "ssl": {...},
      "tls": {...},
      "headers": {...},
      "hsts": {...},
      "redirects": {...},
      "dns": {...},
      "firewall": {...},
      "status": {...},
      "redirect_chain": {...},
      "malware_check": {...},
      "url_parse": {...},
  }
  (keys absent if the endpoint failed or was skipped)
"""

import json
from typing import Any

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.0,
    "low": 0.3,
    "info": 0.0,
}

_IMPORTANT_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _adapt_status(data: dict) -> list[dict]:
    findings = []
    if data.get("isUp") is False:
        findings.append({
            "type": "host_down",
            "detail": f"Target is DOWN (status: {data.get('responseCode', '?')})",
            "severity": "medium",
            "evidence": json.dumps(data)[:300],
        })
    return findings


def _adapt_security_headers(data: dict) -> tuple[list[dict], str]:
    findings = []
    missing = list(data.get("missing", []))
    present = list(data.get("present", []))
    score = data.get("score", "?")
    raw = f"security-headers: score={score}, missing={missing}"

    for header in missing:
        severity = "high" if header in ("Content-Security-Policy", "Strict-Transport-Security") else "medium"
        findings.append({
            "type": "missing_security_header",
            "detail": f"Missing security header: {header}",
            "severity": severity,
            "evidence": header,
        })

    info_present = ", ".join(present[:5]) if present else "none"
    findings.append({
        "type": "security_headers_summary",
        "detail": f"Security headers score: {score} — {len(missing)} missing, {len(present)} present",
        "severity": "info",
        "evidence": info_present,
    })
    return findings, raw


def _adapt_ssl(data: dict) -> tuple[list[dict], str]:
    findings = []
    raw_parts = []
    if "error" in data or data.get("success") is False:
        raw_parts.append(f"ssl: error={data.get('error', 'unknown')}")
        return findings, "\n".join(raw_parts)

    subject = data.get("subject", {})
    issuer = data.get("issuer", {})
    not_after = data.get("notAfter", "")
    raw_parts.append(f"ssl: subject={subject}, issuer={issuer}, expires={not_after}")
    findings.append({
        "type": "ssl_certificate",
        "detail": f"SSL cert: issuer={issuer}, expires={not_after}",
        "severity": "info",
        "evidence": json.dumps(data)[:400],
    })
    return findings, "\n".join(raw_parts)


def _adapt_tls(data: dict) -> tuple[list[dict], str]:
    findings = []
    tls_version = data.get("tlsVersion", "")
    cipher = data.get("cipher", "")
    raw = f"tls: version={tls_version}, cipher={cipher}"

    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append({
            "type": "tls_weakness",
            "detail": f"Deprecated TLS version in use: {tls_version}",
            "severity": "high",
            "evidence": raw,
        })
    elif tls_version:
        findings.append({
            "type": "tls_info",
            "detail": f"TLS: {tls_version}, cipher: {cipher}",
            "severity": "info",
            "evidence": raw,
        })
    return findings, raw


def _adapt_hsts(data: dict) -> tuple[list[dict], str]:
    findings = []
    present = data.get("present", False)
    raw = f"hsts: present={present}"
    if not present:
        findings.append({
            "type": "missing_hsts",
            "detail": "HSTS policy is not configured",
            "severity": "medium",
            "evidence": json.dumps(data)[:200],
        })
    return findings, raw


def _adapt_firewall(data: dict) -> tuple[list[dict], str]:
    findings = []
    has_waf = data.get("hasWaf", False)
    waf_name = data.get("waf", "")
    raw = f"firewall: hasWAF={has_waf}, waf={waf_name}"
    findings.append({
        "type": "waf_detection",
        "detail": f"WAF detected: {waf_name}" if has_waf else "No WAF detected",
        "severity": "info" if has_waf else "low",
        "evidence": raw,
    })
    return findings, raw


def _adapt_redirects(data: dict) -> tuple[list[dict], str]:
    findings = []
    redirects = data.get("redirects", [])
    raw = f"redirects: count={len(redirects)}"
    if len(redirects) > 3:
        findings.append({
            "type": "excessive_redirects",
            "detail": f"Unusual redirect chain ({len(redirects)} hops)",
            "severity": "low",
            "evidence": json.dumps(redirects)[:400],
        })
    return findings, raw


def _adapt_redirect_chain(data: dict) -> tuple[list[dict], str]:
    findings = []
    risk_assessment = data.get("risk_assessment", {})
    risk_level = risk_assessment.get("risk_level", "low")
    total_hops = data.get("total_hops", 0)
    is_safe = data.get("is_safe", True)
    raw = f"redirect_chain: hops={total_hops}, risk={risk_level}, safe={is_safe}"

    severity_map = {"high": "high", "medium": "medium", "low": "info"}
    severity = severity_map.get(risk_level.lower(), "info")

    if not is_safe or risk_level in ("high", "medium"):
        findings.append({
            "type": "redirect_chain_risk",
            "detail": f"Redirect chain ({total_hops} hops) — risk level: {risk_level}",
            "severity": severity,
            "evidence": json.dumps(risk_assessment)[:400],
        })
    return findings, raw


def _adapt_malware_check(data: dict) -> tuple[list[dict], str]:
    findings = []
    is_malicious = data.get("is_malicious", False)
    risk_level = data.get("risk_level", "low")
    detections = data.get("detections", [])
    detection_count = data.get("detection_count", 0)
    raw = f"malware_check: malicious={is_malicious}, detections={detection_count}, risk={risk_level}"

    if is_malicious:
        findings.append({
            "type": "url_malicious",
            "detail": f"URL flagged as malicious by {detection_count} source(s) — risk: {risk_level}",
            "severity": "critical" if risk_level == "high" else "high",
            "evidence": json.dumps(detections)[:400],
        })
    else:
        findings.append({
            "type": "url_clean",
            "detail": "URL not found in malware/phishing databases",
            "severity": "info",
            "evidence": raw,
        })
    return findings, raw


def _adapt_url_parse(data: dict) -> tuple[list[dict], str]:
    findings = []
    is_valid = data.get("is_valid", True)
    suspicious_indicators = data.get("suspicious_indicators", [])
    risk_level = data.get("risk_level", "low")
    raw = f"url_parse: valid={is_valid}, suspicious_indicators={len(suspicious_indicators)}, risk={risk_level}"

    for indicator in suspicious_indicators:
        findings.append({
            "type": "url_suspicious_indicator",
            "detail": f"URL suspicious indicator: {indicator}",
            "severity": "high" if risk_level == "high" else "medium",
            "evidence": str(indicator),
        })
    return findings, raw


def adapt(aggregated: dict[str, Any], pass_number: int, input_data: str) -> dict[str, Any]:
    """
    Translate aggregated Web-Analyzer endpoint responses into SecFlow contract.

    Args:
        aggregated:  dict of {endpoint_name: response_dict} from the orchestrator
        pass_number: current pipeline pass (1-indexed)
        input_data:  the URL that was analyzed

    Returns:
        SecFlow contract dict.
    """
    findings: list[dict] = []
    raw_parts: list[str] = [f"Web analysis for: {input_data}"]

    adapters = {
        "status": _adapt_status,
    }

    # Status
    if "status" in aggregated:
        findings.extend(_adapt_status(aggregated["status"]))
        raw_parts.append(f"status: up={aggregated['status'].get('isUp')}")

    # Security headers
    if "security_headers" in aggregated:
        f, r = _adapt_security_headers(aggregated["security_headers"])
        findings.extend(f); raw_parts.append(r)

    # SSL
    if "ssl" in aggregated:
        f, r = _adapt_ssl(aggregated["ssl"])
        findings.extend(f); raw_parts.extend([r] if r else [])

    # TLS
    if "tls" in aggregated:
        f, r = _adapt_tls(aggregated["tls"])
        findings.extend(f); raw_parts.append(r)

    # HSTS
    if "hsts" in aggregated:
        f, r = _adapt_hsts(aggregated["hsts"])
        findings.extend(f); raw_parts.append(r)

    # Firewall / WAF
    if "firewall" in aggregated:
        f, r = _adapt_firewall(aggregated["firewall"])
        findings.extend(f); raw_parts.append(r)

    # Redirects
    if "redirects" in aggregated:
        f, r = _adapt_redirects(aggregated["redirects"])
        findings.extend(f); raw_parts.append(r)

    # Redirect chain (new endpoint from Url-Analyzer integration)
    if "redirect_chain" in aggregated:
        f, r = _adapt_redirect_chain(aggregated["redirect_chain"])
        findings.extend(f); raw_parts.append(r)

    # Malware check (new endpoint from Url-Analyzer integration)
    if "malware_check" in aggregated:
        f, r = _adapt_malware_check(aggregated["malware_check"])
        findings.extend(f); raw_parts.append(r)

    # URL parser (new endpoint from Url-Analyzer integration)
    if "url_parse" in aggregated:
        f, r = _adapt_url_parse(aggregated["url_parse"])
        findings.extend(f); raw_parts.append(r)

    risk_score = min(
        10.0,
        sum(_SEVERITY_WEIGHTS.get(f["severity"], 0.0) for f in findings),
    )

    return {
        "analyzer": "web",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": round(risk_score, 2),
        "raw_output": "\n".join(raw_parts),
    }
