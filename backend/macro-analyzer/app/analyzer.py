"""
VBA / macro analyzer wrapping oletools.olevba.

Supports all OLE2 and OpenXML Office formats:
  OLE2   — .doc, .xls, .ppt (and their macro-enabled variants)
  OpenXML — .docx, .xlsx, .pptx, .xlsm, .docm
  RTF     — .rtf

Returns a rich dict that the routes.py layer serialises to JSON.
"""

import logging
from typing import Any

log = logging.getLogger("macro-analyzer.analyzer")

# Indicator category names returned by olevba.analyze_macros()
_KNOWN_CATS = frozenset({
    "AutoExec", "Suspicious", "IOC",
    "Hex String", "Base64 String", "Dridex String", "VBA String",
})


def analyze_file(file_path: str, original_name: str = "") -> dict[str, Any]:
    """
    Run olevba on an Office/RTF document and return a structured result.

    Result shape:
    {
        "filename":    str,
        "file_type":   str,   # "OLE", "OpenXML", "XML", "RTF", etc.
        "has_macros":  bool,
        "macro_count": int,
        "macros": [
            {"stream": str, "module": str, "code": str}
        ],
        "indicators": {
            "<Category>": [{"keyword": str, "description": str}]
        },
        "iocs": [{"value": str, "context": str}],
        "flags": {
            "auto_exec":  bool,
            "suspicious": bool,
            "has_ioc":    bool,
            "obfuscated": bool,
        },
        "risk_level": "clean" | "macro_present" | "suspicious" | "malicious",
        "xlm_macros": str | None,   # Excel 4 / XLM macros (if present and XLMMacroDeobfuscator available)
    }
    """
    from oletools.olevba import VBA_Parser  # imported here so import errors surface cleanly

    display_name = original_name or file_path

    with open(file_path, "rb") as fh:
        data = fh.read()

    vba = VBA_Parser(display_name, data=data)

    result: dict[str, Any] = {
        "filename":    display_name,
        "file_type":   vba.type or "unknown",
        "has_macros":  False,
        "macro_count": 0,
        "macros":      [],
        "indicators":  {},
        "iocs":        [],
        "flags": {
            "auto_exec":  False,
            "suspicious": False,
            "has_ioc":    False,
            "obfuscated": False,
        },
        "risk_level":  "clean",
        "xlm_macros":  None,
    }

    # ── Macro detection ────────────────────────────────────────────────────────
    try:
        result["has_macros"] = vba.detect_vba_macros()
    except Exception as exc:
        log.warning(f"detect_vba_macros raised: {exc}")
        return result

    if not result["has_macros"]:
        return result

    # ── Extract macro source code ──────────────────────────────────────────────
    try:
        for (_, stream_path, vba_filename, vba_code) in vba.extract_macros():
            result["macros"].append({
                "stream": stream_path or "",
                "module": vba_filename or "",
                "code":   vba_code    or "",
            })
    except Exception as exc:
        log.warning(f"extract_macros raised: {exc}")

    result["macro_count"] = len(result["macros"])

    # ── Analyze macro indicators ───────────────────────────────────────────────
    try:
        for (itype, keyword, description) in vba.analyze_macros():
            result["indicators"].setdefault(itype, []).append({
                "keyword":     keyword,
                "description": description,
            })
            if itype == "IOC":
                result["iocs"].append({"value": keyword, "context": description})
    except Exception as exc:
        log.warning(f"analyze_macros raised: {exc}")

    ind = result["indicators"]
    flags = result["flags"]
    flags["auto_exec"]  = bool(ind.get("AutoExec"))
    flags["suspicious"] = bool(ind.get("Suspicious"))
    flags["has_ioc"]    = bool(ind.get("IOC"))
    flags["obfuscated"] = bool(ind.get("Hex String") or ind.get("Base64 String"))

    # ── XLM / Excel 4 macros (if XLMMacroDeobfuscator is installed) ───────────
    try:
        xlm = vba.xlm_macros
        if xlm:
            result["xlm_macros"] = str(xlm)
    except Exception:
        pass

    # ── Risk level ─────────────────────────────────────────────────────────────
    if flags["auto_exec"] and flags["suspicious"]:
        result["risk_level"] = "malicious"
    elif flags["suspicious"] or flags["has_ioc"] or flags["obfuscated"]:
        result["risk_level"] = "suspicious"
    else:
        result["risk_level"] = "macro_present"

    return result
