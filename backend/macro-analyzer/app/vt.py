"""
VirusTotal API v3 helper for macro-analyzer.

Looks up the file by SHA-256. If not yet known to VT, uploads it and polls
for the completion of the analysis.

Returns a normalised dict that macro_adapter.py consumes.
"""

import hashlib
import logging
import time
from typing import Any

import requests

log = logging.getLogger("macro-analyzer.vt")

VT_BASE         = "https://www.virustotal.com/api/v3"
_TIMEOUT        = 30   # seconds – regular GETs
_UPLOAD_TIMEOUT = 60   # seconds – file upload
_POLL_INTERVAL  = 5    # seconds between analysis-status polls
_MAX_POLLS      = 6    # give up after ~30 s of polling


# ── internal helpers ──────────────────────────────────────────────────────────

def _sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65_536), b""):
            h.update(chunk)
    return h.hexdigest()


def _headers(api_key: str) -> dict[str, str]:
    return {"x-apikey": api_key, "Accept": "application/json"}


def _get_by_hash(sha256: str, api_key: str) -> dict[str, Any] | None:
    """Return the `attributes` dict if VT already knows this hash, else None."""
    try:
        r = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers=_headers(api_key),
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            return r.json().get("data", {}).get("attributes", {})
        if r.status_code == 404:
            return None
        log.warning(f"[vt] hash lookup HTTP {r.status_code}: {r.text[:200]}")
        return None
    except Exception as exc:
        log.warning(f"[vt] hash lookup failed: {exc}")
        return None


def _upload(file_path: str, api_key: str) -> str | None:
    """Upload *file_path* to VT. Returns the analysis_id string or None."""
    try:
        with open(file_path, "rb") as fh:
            r = requests.post(
                f"{VT_BASE}/files",
                headers=_headers(api_key),
                files={"file": fh},
                timeout=_UPLOAD_TIMEOUT,
            )
        r.raise_for_status()
        return r.json().get("data", {}).get("id")
    except Exception as exc:
        log.warning(f"[vt] upload failed: {exc}")
        return None


def _poll_analysis(analysis_id: str, api_key: str) -> dict[str, Any] | None:
    """Poll /analyses/{id} until status == 'completed'. Returns attributes or None."""
    for _ in range(_MAX_POLLS):
        time.sleep(_POLL_INTERVAL)
        try:
            r = requests.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=_headers(api_key),
                timeout=_TIMEOUT,
            )
            if r.status_code != 200:
                continue
            obj   = r.json().get("data", {})
            attrs = obj.get("attributes", {})
            if attrs.get("status") == "completed":
                # Try to fetch the full file report via the hash in meta
                sha = obj.get("meta", {}).get("file_info", {}).get("sha256")
                if sha:
                    full = _get_by_hash(sha, api_key)
                    if full:
                        return full
                # Fallback – build minimal attrs from analysis object
                return {
                    "last_analysis_stats":   attrs.get("stats", {}),
                    "last_analysis_results": attrs.get("results", {}),
                }
        except Exception as exc:
            log.warning(f"[vt] poll failed: {exc}")
    log.warning("[vt] timed out waiting for analysis to complete")
    return None


# ── public API ────────────────────────────────────────────────────────────────

def scan_file(file_path: str, api_key: str) -> dict[str, Any]:
    """
    Look up or upload *file_path* on VirusTotal.

    Returns:
        {
            "success":          bool,
            "sha256":           str,
            "stats":            {"malicious": int, "suspicious": int, ...},
            "results":          {"<Engine>": {"category": str, "result": str|None}, ...},
            "meaningful_name":  str,
            "type_description": str,
            "error":            str | None,
        }
    """
    sha256 = _sha256(file_path)
    attrs  = _get_by_hash(sha256, api_key)

    if attrs is None:
        analysis_id = _upload(file_path, api_key)
        if analysis_id:
            attrs = _poll_analysis(analysis_id, api_key)

    if attrs is None:
        return {
            "success":          False,
            "sha256":           sha256,
            "stats":            {},
            "results":          {},
            "meaningful_name":  "",
            "type_description": "",
            "error":            "VT analysis unavailable (upload or polling failed)",
        }

    return {
        "success":          True,
        "sha256":           sha256,
        "stats":            attrs.get("last_analysis_stats")   or attrs.get("stats",   {}),
        "results":          attrs.get("last_analysis_results") or attrs.get("results", {}),
        "meaningful_name":  attrs.get("meaningful_name",  ""),
        "type_description": attrs.get("type_description", ""),
        "error":            None,
    }
