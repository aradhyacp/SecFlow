"""
Macro Analyzer adapter — translates macro-analyzer JSON to the SecFlow contract.
"""

import json
from typing import Any

# Risk score per risk_level classification
_RISK_SCORE: dict[str, float] = {
    "malicious":     9.5,
    "suspicious":    6.5,
    "macro_present": 3.0,
    "clean":         0.5,
}

# Severity per olevba indicator category
_INDICATOR_SEV: dict[str, str] = {
    "AutoExec":     "critical",
    "Suspicious":   "high",
    "IOC":          "high",
    "Hex String":   "medium",
    "Base64 String":"medium",
    "Dridex String":"critical",
    "VBA String":   "low",
}


def adapt(raw: dict, pass_number: int, file_path: str) -> dict[str, Any]:
    """
    Translate the macro-analyzer /analyze response to the SecFlow contract.

    raw — full JSON response body (may contain "success" key which we ignore).
    """
    findings: list[dict] = []
    raw_parts: list[str] = []

    # Unpack fields (tolerant — all optional)
    risk_level  = raw.get("risk_level",  "clean")
    has_macros  = raw.get("has_macros",  False)
    macro_count = raw.get("macro_count", 0)
    file_type   = raw.get("file_type",   "unknown")
    filename    = raw.get("filename",    file_path)
    flags       = raw.get("flags",       {})
    indicators  = raw.get("indicators",  {})
    iocs        = raw.get("iocs",        [])
    macros      = raw.get("macros",      [])
    xlm_macros  = raw.get("xlm_macros")

    # ── Finding 1: overall macro presence / verdict ────────────────────────────
    if has_macros:
        sev = (
            "critical" if risk_level == "malicious" else
            "high"     if risk_level == "suspicious" else
            "medium"
        )
        active_flags = [k for k, v in flags.items() if v]
        findings.append({
            "type":     f"macro_{risk_level}",
            "detail":   (
                f"{macro_count} VBA macro module(s) found in {filename} ({file_type}). "
                f"Flags: {', '.join(active_flags) if active_flags else 'none'}."
            ),
            "severity": sev,
            "evidence": json.dumps(flags),
        })
        raw_parts.append(
            f"VBA macros: {macro_count} module(s), risk={risk_level}, "
            f"flags=[{', '.join(active_flags)}]"
        )
    else:
        findings.append({
            "type":     "macro_clean",
            "detail":   f"No VBA macros detected in {filename} ({file_type}).",
            "severity": "info",
            "evidence": "",
        })
        raw_parts.append(f"No macros in {filename}")

    # ── Finding 2: per-category indicator breakdown ────────────────────────────
    for category, items in indicators.items():
        if not items:
            continue
        sev = _INDICATOR_SEV.get(category, "low")
        # Escalate AutoExec severity if suspicious flag is also set
        if category == "AutoExec" and flags.get("suspicious"):
            sev = "critical"

        keywords = [i.get("keyword", "") for i in items]
        summary  = ", ".join(keywords[:10])
        overflow = f" … (+{len(items) - 10} more)" if len(items) > 10 else ""

        findings.append({
            "type":     f"macro_indicator_{category.lower().replace(' ', '_')}",
            "detail":   f"{category}: {summary}{overflow}",
            "severity": sev,
            "evidence": json.dumps(items),  # list of {keyword, description} — rendered as table
        })
        raw_parts.append(f"  [{category}] {summary}")

    # ── Finding 3: extracted IOCs (enables AI chain to recon/web) ─────────────
    if iocs:
        ioc_values = [i.get("value", "") for i in iocs]
        summary = ", ".join(ioc_values[:5])
        overflow = f" … (+{len(ioc_values) - 5} more)" if len(ioc_values) > 5 else ""
        findings.append({
            "type":     "macro_ioc",
            "detail":   f"IOCs extracted from macros: {summary}{overflow}",
            "severity": "high",
            "evidence": json.dumps(ioc_values),  # plain list — rendered as chip list
        })
        # Emit IOCs into raw_output so the AI extraction pipeline picks them up
        raw_parts.append("IOCs:")
        raw_parts.extend(f"  {v}" for v in ioc_values)

    # ── Finding 4: full macro source (collapsible in HTML, uncapped) ───────────
    if macros:
        code_sections = []
        for m in macros:
            header = f"--- Module: {m.get('module', '?')} (stream: {m.get('stream', '?')}) ---"
            code_sections.append(f"{header}\n{m.get('code', '')}")
        full_code = "\n\n".join(code_sections)
        findings.append({
            "type":     "macro_source",
            "detail":   f"Full VBA source across {len(macros)} module(s)",
            "severity": "info",
            "evidence": full_code,  # full, uncapped — report renderer uses <details>
        })
        raw_parts.append(full_code)

    # ── Finding 5: XLM / Excel 4 macros (if present) ──────────────────────────
    if xlm_macros:
        findings.append({
            "type":     "macro_xlm",
            "detail":   "Excel 4 (XLM) macros detected and deobfuscated",
            "severity": "high",
            "evidence": xlm_macros,
        })
        raw_parts.append(f"XLM macros: {xlm_macros[:200]}")

    # ── Finding 6: VirusTotal threat intel (present when VIRUSTOTAL_API_KEY set) ──
    vt = raw.get("vt")
    if vt:
        if not vt.get("success"):
            vt_error = vt.get("error", "VT scan failed")
            findings.append({
                "type":     "error",
                "detail":   f"VirusTotal: {vt_error}",
                "severity": "low",
                "evidence": "",
            })
            raw_parts.append(f"VT error: {vt_error}")
        else:
            stats       = vt.get("stats", {})
            results_map = vt.get("results", {})
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            total       = sum(stats.values()) if stats else 0
            raw_parts.append(
                f"VT: malicious={malicious}, suspicious={suspicious}, total={total}"
            )
            if malicious > 0 or suspicious > 0:
                sev = "critical" if malicious >= 5 else "high" if malicious > 0 else "medium"
                findings.append({
                    "type":     "malware_detection",
                    "detail":   (
                        f"VirusTotal: {malicious} malicious, {suspicious} suspicious "
                        f"out of {total} engines"
                    ),
                    "severity": sev,
                    "evidence": json.dumps(stats),
                })
                for engine, res in list(results_map.items())[:10]:
                    if res.get("category") in ("malicious", "suspicious"):
                        findings.append({
                            "type":     "av_detection",
                            "detail":   f"{engine}: {res.get('result', 'detected')}",
                            "severity": "high" if res.get("category") == "malicious" else "medium",
                            "evidence": json.dumps(res),
                        })
                        raw_parts.append(f"  [{engine}] {res.get('result', '')}")
            else:
                findings.append({
                    "type":     "malware_detection",
                    "detail":   f"VirusTotal: no detections ({total} engines clean)",
                    "severity": "info",
                    "evidence": json.dumps(stats),
                })

    # ── Risk score: base from oletools, raised if VT confirms malicious ────────
    base_score = _RISK_SCORE.get(risk_level, 0.0)
    if vt and vt.get("success"):
        malicious = vt.get("stats", {}).get("malicious", 0)
        if malicious >= 5:
            base_score = max(base_score, 9.5)
        elif malicious > 0:
            base_score = max(base_score, 7.0)

    return {
        "analyzer":   "macro",
        "pass":       pass_number,
        "input":      file_path,
        "findings":   findings,
        "risk_score": base_score,
        "raw_output": "\n".join(raw_parts),
    }
