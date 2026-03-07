"""
Recon Adapter — translates Recon-Analyzer responses to the SecFlow contract.

Real Recon-Analyzer endpoints:
  POST /api/Recon-Analyzer/scan       → IP / domain threat intel
  POST /api/Recon-Analyzer/footprint  → email / phone / username OSINT

Request body key is "query" (not "target").
API prefix uses capital R and A — exact casing required.
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


def _adapt_scan(raw: dict[str, Any]) -> tuple[list[dict], list[str]]:
    """Parse /scan response (IP or domain) into findings + raw_parts."""
    findings: list[dict] = []
    raw_parts: list[str] = []
    query = raw.get("query", "unknown")

    # ipapi — geolocation
    ipapi = raw.get("ipapi", {})
    ip_info = ipapi.get("ip_info", [])
    if ip_info:
        entry = ip_info[0]
        detail = (
            f"IP geolocation: country={entry.get('country', '?')}, "
            f"ISP={entry.get('isp', '?')}, AS={entry.get('as', '?')}"
        )
        raw_parts.append(f"ipapi: {json.dumps(entry)[:300]}")
        findings.append({
            "type": "geolocation",
            "detail": detail,
            "severity": "info",
            "evidence": json.dumps(entry)[:400],
        })

    # talos — blocklist check
    talos = raw.get("talos", {})
    if talos:
        blacklisted = talos.get("blacklisted", False)
        raw_parts.append(f"talos: blacklisted={blacklisted}")
        if blacklisted:
            findings.append({
                "type": "blocklist_hit",
                "detail": f"Cisco Talos blocklist: {query} is BLACKLISTED",
                "severity": "critical",
                "evidence": json.dumps(talos),
            })
        else:
            findings.append({
                "type": "blocklist_check",
                "detail": f"Cisco Talos blocklist: {query} is clean",
                "severity": "info",
                "evidence": json.dumps(talos),
            })

    # tor exit node check
    tor = raw.get("tor", {})
    if tor:
        is_tor = tor.get("is_tor_exit", False)
        raw_parts.append(f"tor: is_tor_exit={is_tor}")
        if is_tor:
            findings.append({
                "type": "tor_exit_node",
                "detail": f"{query} is a known Tor exit node",
                "severity": "high",
                "evidence": json.dumps(tor),
            })

    # tranco ranking (domains only)
    tranco = raw.get("tranco", {})
    if tranco:
        found = tranco.get("found", False)
        rank = tranco.get("rank")
        raw_parts.append(f"tranco: found={found}, rank={rank}")
        if found and rank:
            findings.append({
                "type": "domain_rank",
                "detail": f"Tranco rank: #{rank} (well-known domain)",
                "severity": "info",
                "evidence": json.dumps(tranco),
            })

    # threatfox IOC (domains only)
    threatfox = raw.get("threatfox", {})
    if threatfox and threatfox.get("found", False):
        malware = threatfox.get("malware", "unknown malware")
        confidence = threatfox.get("confidence_level", 0)
        raw_parts.append(f"threatfox: malware={malware}, confidence={confidence}")
        severity = "critical" if confidence >= 75 else "high"
        findings.append({
            "type": "ioc_match",
            "detail": f"ThreatFox IOC match: {malware} (confidence: {confidence}%)",
            "severity": severity,
            "evidence": json.dumps(threatfox),
        })

    return findings, raw_parts


def _adapt_footprint(raw: dict[str, Any]) -> tuple[list[dict], list[str]]:
    """Parse /footprint response (email/phone/username) into findings + raw_parts."""
    findings: list[dict] = []
    raw_parts: list[str] = []
    query = raw.get("query", "unknown")
    input_type = raw.get("type", "unknown")

    raw_parts.append(f"footprint type: {input_type}, query: {query}")

    if input_type == "email":
        email_scan = raw.get("email_scan", {})
        exposed = email_scan.get("exposed", False)
        breach_count = email_scan.get("breach_count", 0)
        risk = email_scan.get("risk", [])

        raw_parts.append(f"email: exposed={exposed}, breaches={breach_count}")
        if exposed:
            risk_label = risk[0].get("risk_label", "Unknown") if risk else "Unknown"
            severity = "critical" if "Critical" in risk_label else "high" if breach_count > 5 else "medium"
            findings.append({
                "type": "email_breach",
                "detail": f"Email exposed in {breach_count} breach(es) — risk: {risk_label}",
                "severity": severity,
                "evidence": json.dumps(email_scan)[:500],
            })

            for breach in email_scan.get("breaches", [])[:5]:
                raw_parts.append(f"  breach: {breach.get('breach', '?')} ({breach.get('domain', '?')})")
        else:
            findings.append({
                "type": "email_check",
                "detail": f"Email {query} not found in breach databases",
                "severity": "info",
                "evidence": json.dumps(email_scan)[:200],
            })

    elif input_type == "phone":
        phone_scan = raw.get("phone_scan", {})
        valid = phone_scan.get("valid", False)
        raw_parts.append(f"phone: valid={valid}, carrier={phone_scan.get('carrier', '?')}")
        if valid:
            findings.append({
                "type": "phone_validation",
                "detail": (
                    f"Phone valid: {phone_scan.get('country_name', '?')}, "
                    f"carrier={phone_scan.get('carrier', '?')}, "
                    f"type={phone_scan.get('line_type', '?')}"
                ),
                "severity": "info",
                "evidence": json.dumps(phone_scan)[:300],
            })

    elif input_type == "username":
        username_scan = raw.get("username_scan", [])
        platform_count = len(username_scan)
        raw_parts.append(f"username: found on {platform_count} platforms")
        if platform_count > 0:
            findings.append({
                "type": "username_presence",
                "detail": f"Username '{query}' found on {platform_count} platform(s)",
                "severity": "medium" if platform_count > 5 else "low",
                "evidence": json.dumps(username_scan[:10])[:400],
            })
            for site in username_scan[:5]:
                raw_parts.append(f"  {site.get('site', '?')}: {site.get('url', '?')}")

    return findings, raw_parts


def adapt(raw: dict[str, Any], pass_number: int, input_data: str) -> dict[str, Any]:
    """
    Translate Recon-Analyzer response into SecFlow contract.

    Args:
        raw:         JSON response from /scan or /footprint
        pass_number: current pipeline pass (1-indexed)
        input_data:  the IP / domain / email / phone / username that was queried

    Returns:
        SecFlow contract dict.
    """
    findings: list[dict] = []
    raw_parts: list[str] = [f"Recon analysis for: {input_data}"]

    # Detect which endpoint was called by response shape
    if "ipapi" in raw or "talos" in raw or "tor" in raw:
        f, r = _adapt_scan(raw)
    elif "type" in raw and raw["type"] in ("email", "phone", "username"):
        f, r = _adapt_footprint(raw)
    else:
        # Fallback: treat full response as raw output
        raw_parts.append(json.dumps(raw)[:1000])
        f, r = [], [json.dumps(raw)[:1000]]

    findings.extend(f)
    raw_parts.extend(r)

    risk_score = min(
        10.0,
        sum(_SEVERITY_WEIGHTS.get(f["severity"], 0.0) for f in findings),
    )

    return {
        "analyzer": "recon",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": round(risk_score, 2),
        "raw_output": "\n".join(raw_parts),
    }
