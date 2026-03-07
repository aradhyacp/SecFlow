"""
Steg Adapter — bridges the async Steg-Analyzer API to the SecFlow contract.

Steg-Analyzer is an ASYNC service:
  1. POST /api/steg-analyzer/upload  (field: "image") → {"submission_hash": "..."}
  2. Poll GET /api/steg-analyzer/status/<hash> until status == "completed" or "error"
  3. GET /api/steg-analyzer/result/<hash> → {"results": {...}}

The orchestrator calls _call_steg_analyzer() which handles all three steps,
then passes the result dict to adapt().
"""

import json
import logging
import time
from typing import Any

log = logging.getLogger("secflow.steg_adapter")

_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.0,
    "low": 0.3,
    "info": 0.0,
}

# Tools that suggest meaningful hidden content when they produce non-empty output
_HIGH_SEVERITY_TOOLS = {"binwalk", "foremost", "steghide", "outguess", "zsteg", "jsteg", "jpseek"}
_MEDIUM_SEVERITY_TOOLS = {"strings", "openstego"}


def _severity_for_tool(tool_name: str, result: dict) -> str:
    """Assign severity based on tool name and whether extraction succeeded."""
    status = result.get("status", "error")
    if status != "ok":
        return "info"

    has_output = bool(result.get("output") or result.get("download"))
    if not has_output:
        return "info"

    tool = tool_name.lower()
    if tool in _HIGH_SEVERITY_TOOLS:
        return "critical" if result.get("download") else "high"
    if tool in _MEDIUM_SEVERITY_TOOLS:
        return "medium"
    return "low"


def adapt(results_payload: dict[str, Any], pass_number: int, input_data: str) -> dict[str, Any]:
    """
    Translate Steg-Analyzer result payload into SecFlow contract.

    Args:
        results_payload: the dict from GET /api/steg-analyzer/result/<hash>
                         Expected shape: {"results": {"binwalk": {...}, "zsteg": {...}, ...}}
        pass_number:     current pipeline pass (1-indexed)
        input_data:      path to the image that was analyzed

    Returns:
        SecFlow contract dict (includes "extracted_files").
    """
    findings: list[dict] = []
    raw_parts: list[str] = []
    extracted_files: list[str] = []

    results: dict[str, Any] = results_payload.get("results", {})

    for tool_name, tool_result in results.items():
        if not isinstance(tool_result, dict):
            continue

        status = tool_result.get("status", "error")
        raw_parts.append(f"[{tool_name}] status={status}")

        if status == "error":
            error_msg = tool_result.get("error", "unknown error")
            raw_parts.append(f"  error: {error_msg}")
            # Tool errors are just info — don't pollute findings
            continue

        output = tool_result.get("output")
        note = tool_result.get("note", "")
        download = tool_result.get("download")

        if output:
            output_str = json.dumps(output) if not isinstance(output, str) else output
            raw_parts.append(f"  output: {output_str[:500]}")

        if download:
            raw_parts.append(f"  download: {download}")
            extracted_files.append(download)

        severity = _severity_for_tool(tool_name, tool_result)
        if severity in ("critical", "high", "medium"):
            detail_parts = [f"{tool_name} detected steganographic content"]
            if note:
                detail_parts.append(note)
            findings.append({
                "type": "steg_detection",
                "detail": " — ".join(detail_parts),
                "severity": severity,
                "evidence": (json.dumps(output)[:400] if output else "") + (f"\ndownload: {download}" if download else ""),
                "extracted_path": download,
            })
        elif output:
            findings.append({
                "type": "steg_info",
                "detail": f"{tool_name}: analysis complete",
                "severity": "info",
                "evidence": (json.dumps(output)[:200] if output else ""),
                "extracted_path": None,
            })

    # Roll up risk score
    risk_score = min(
        10.0,
        sum(_SEVERITY_WEIGHTS.get(f["severity"], 0.0) for f in findings),
    )

    return {
        "analyzer": "steg",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": round(risk_score, 2),
        "raw_output": "\n".join(raw_parts),
        "extracted_files": extracted_files,
    }
