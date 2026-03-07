"""
URL Adapter — placeholder for any future url-analyzer sub-results.

The url-analyzer service has been merged into the web-analyzer (see Web-Analyzer
integration history). This adapter is kept for structural completeness and forwards
any legacy url-analyzer responses to the web adapter format.
"""

from typing import Any

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.0,
    "low": 0.3,
    "info": 0.0,
}


def adapt(raw: dict[str, Any], pass_number: int, input_data: str) -> dict[str, Any]:
    """
    Translate url-analyzer response into SecFlow contract.
    Wraps the raw response as a single finding for AI consumption.

    Args:
        raw:         JSON response from the url-analyzer service
        pass_number: current pipeline pass (1-indexed)
        input_data:  the URL that was analyzed

    Returns:
        SecFlow contract dict.
    """
    findings: list[dict] = []
    raw_parts: list[str] = [f"URL analysis for: {input_data}"]

    if raw:
        raw_parts.append(str(raw)[:2000])
        findings.append({
            "type": "url_analysis",
            "detail": f"URL analysis completed for {input_data}",
            "severity": "info",
            "evidence": str(raw)[:500],
        })

    risk_score = min(
        10.0,
        sum(_SEVERITY_WEIGHTS.get(f["severity"], 0.0) for f in findings),
    )

    return {
        "analyzer": "url",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": round(risk_score, 2),
        "raw_output": "\n".join(raw_parts),
    }
