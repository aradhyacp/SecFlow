"""
Pipeline Orchestrator — the core analysis loop.

Coordinates all analyzer services via HTTP, runs adapters to normalize
responses, accumulates findings, and drives the AI routing loop.

Key facts about each analyzer's real API (deviates from generic docs):

Malware-Analyzer (port 5000 internal / 5001 host):
  - TWO separate calls required:
    1. POST /api/malware-analyzer/file-analysis  (VirusTotal, 60s)
    2. POST /api/malware-analyzer/decompile      (Ghidra, 180s)
  - Both merged as {"vt": ..., "decompile": ...} before adapter

Steg-Analyzer (port 5002):
  - ASYNC — three steps:
    1. POST /api/steg-analyzer/upload   field="image" → {"submission_hash": "..."}
    2. Poll  GET  /api/steg-analyzer/status/<hash>  until completed/error
    3. GET   /api/steg-analyzer/result/<hash>       → {"results": {...}}

Recon-Analyzer (port 5000 internal / 5003 host):
  - POST /api/Recon-Analyzer/scan   {"query": "ip_or_domain"}
  - POST /api/Recon-Analyzer/footprint  {"query": "..."}
  - Key is "query", prefix capital R and A

Web-Analyzer (port 5000 internal / 5005 host):
  - 34 individual GET endpoints with ?url= param
  - No combined POST endpoint
  - Calls the security-critical subset and aggregates
"""

import logging
import os
import re
import time
from typing import Any
from urllib.parse import urlparse

import requests

from app.classifier.classifier import classify, get_file_head
from app.ai.engine import decide_next
from app.store.findings_store import FindingsStore
from app.adapters import malware_adapter, steg_adapter, recon_adapter, url_adapter, web_adapter

log = logging.getLogger("secflow.orchestrator")

# Docker-internal service base URLs (overridable via env vars)
_MALWARE_BASE = os.getenv("MALWARE_ANALYZER_URL", "http://malware-analyzer:5000/api/malware-analyzer")
_STEG_BASE    = os.getenv("STEG_ANALYZER_URL",    "http://steg-analyzer:5000/api/steg-analyzer")
_RECON_BASE   = os.getenv("RECON_ANALYZER_URL",   "http://recon-analyzer:5000/api/Recon-Analyzer")
_WEB_BASE     = os.getenv("WEB_ANALYZER_URL",     "http://web-analyzer:5000/api/web-analyzer")

# Steg-Analyzer async polling settings
_STEG_POLL_INTERVAL = 3   # seconds between status checks
_STEG_MAX_WAIT      = 300 # 5 minutes max


# ── Analyzer caller functions ──────────────────────────────────────────────────

def _call_malware(file_path: str, pass_number: int) -> dict[str, Any]:
    """Call malware-analyzer: two requests (VT + Ghidra), merge, then adapt."""
    vt_resp: dict = {}
    decomp_resp: dict = {}

    # Call 1 — VirusTotal file analysis
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_MALWARE_BASE}/file-analysis",
                files={"file": f},
                timeout=60,
            )
        r.raise_for_status()
        vt_resp = r.json()
        log.info(f"[malware] VT analysis complete for {file_path}")
    except Exception as e:
        log.error(f"[malware] VT call failed: {e}")
        vt_resp = {"success": False, "error": str(e)}

    # Call 2 — Ghidra decompile + objdump
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_MALWARE_BASE}/decompile",
                files={"file": f},
                timeout=180,
            )
        r.raise_for_status()
        decomp_resp = r.json()
        log.info(f"[malware] Decompile complete for {file_path}")
    except Exception as e:
        log.error(f"[malware] Decompile call failed: {e}")
        decomp_resp = {"success": False, "error": str(e)}

    return malware_adapter.adapt(
        {"vt": vt_resp, "decompile": decomp_resp},
        pass_number,
        file_path,
    )


def _call_steg(file_path: str, pass_number: int) -> dict[str, Any]:
    """Call steg-analyzer: async upload → poll → fetch result, then adapt."""
    # Step 1 — upload
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_STEG_BASE}/upload",
                files={"image": f},
                timeout=30,
            )
        r.raise_for_status()
        submission_hash = r.json().get("submission_hash")
        if not submission_hash:
            raise ValueError("No submission_hash in upload response")
        log.info(f"[steg] Upload queued, hash={submission_hash}")
    except Exception as e:
        log.error(f"[steg] Upload failed: {e}")
        return steg_adapter.adapt({}, pass_number, file_path)

    # Step 2 — poll status
    deadline = time.time() + _STEG_MAX_WAIT
    while time.time() < deadline:
        try:
            r = requests.get(f"{_STEG_BASE}/status/{submission_hash}", timeout=10)
            r.raise_for_status()
            status = r.json().get("status", "")
            log.debug(f"[steg] status={status}")
            if status == "completed":
                break
            if status == "error":
                log.error("[steg] Analysis errored out")
                return steg_adapter.adapt({}, pass_number, file_path)
        except Exception as e:
            log.warning(f"[steg] Status poll error: {e}")
        time.sleep(_STEG_POLL_INTERVAL)
    else:
        log.error("[steg] Polling timed out")
        return steg_adapter.adapt({}, pass_number, file_path)

    # Step 3 — fetch result
    try:
        r = requests.get(f"{_STEG_BASE}/result/{submission_hash}", timeout=30)
        r.raise_for_status()
        result_payload = r.json()
        log.info(f"[steg] Results fetched for hash={submission_hash}")
    except Exception as e:
        log.error(f"[steg] Result fetch failed: {e}")
        return steg_adapter.adapt({}, pass_number, file_path)

    return steg_adapter.adapt(result_payload, pass_number, file_path)


def _call_recon(query: str, pass_number: int) -> dict[str, Any]:
    """
    Call recon-analyzer /scan for IP/domain or /footprint for email/phone/username.
    Key is "query" (not "target").
    """
    # Determine which endpoint to use based on input format
    ip_re = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    domain_re = re.compile(
        r"^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
    )

    is_ip_or_domain = bool(ip_re.match(query)) or bool(domain_re.match(query))
    endpoint = "scan" if is_ip_or_domain else "footprint"

    try:
        r = requests.post(
            f"{_RECON_BASE}/{endpoint}",
            json={"query": query},
            timeout=60,
        )
        r.raise_for_status()
        raw = r.json()
        log.info(f"[recon] {endpoint} complete for {query}")
    except Exception as e:
        log.error(f"[recon] Call failed: {e}")
        raw = {}

    return recon_adapter.adapt(raw, pass_number, query)


def _call_web(url: str, pass_number: int) -> dict[str, Any]:
    """
    Call the security-critical subset of Web-Analyzer GET endpoints.
    Aggregates results, then adapts.
    """
    params = {"url": url}
    aggregated: dict[str, Any] = {}

    # Prioritized list: (endpoint_name, route, timeout)
    endpoints = [
        ("status",           "status",           15),
        ("security_headers", "security-headers", 20),
        ("tls",              "tls",              20),
        ("ssl",              "ssl",              20),
        ("hsts",             "hsts",             15),
        ("firewall",         "firewall",         20),
        ("redirects",        "redirects",        20),
        ("headers",          "headers",          15),
        ("redirect_chain",   "redirect-chain",   30),
        ("malware_check",    "malware-check",    30),
        ("url_parse",        "url-parse",        10),
        ("dns",              "dns",              15),
    ]

    for key, route, timeout in endpoints:
        try:
            r = requests.get(
                f"{_WEB_BASE}/{route}",
                params=params,
                timeout=timeout,
            )
            if r.status_code == 200:
                aggregated[key] = r.json()
                log.debug(f"[web] /{route} OK")
            else:
                log.warning(f"[web] /{route} returned {r.status_code}")
        except requests.exceptions.Timeout:
            log.warning(f"[web] /{route} timed out")
        except Exception as e:
            log.warning(f"[web] /{route} error: {e}")

    return web_adapter.adapt(aggregated, pass_number, url)


# ── Main pipeline loop ─────────────────────────────────────────────────────────

_CALLER_MAP = {
    "malware": _call_malware,
    "steg":    _call_steg,
    "recon":   _call_recon,
    "web":     _call_web,
}


def _normalize_target(tool: str, target: str) -> str | None:
    """
    Last-mile normalization before passing target to an analyzer.
    - recon: must be a bare IP or hostname (no scheme, no path)
    - web:   must be a full URL with http(s):// scheme
    Returns None if the target cannot be made valid.
    """
    target = target.strip().rstrip("/")
    if not target:
        return None

    if tool == "recon":
        try:
            host = urlparse(target if "://" in target else f"https://{target}").hostname or ""
        except Exception:
            host = ""
        if not host or host.startswith(".") or "." not in host:
            log.warning(f"[pipeline] Cannot normalize recon target: {target!r}")
            return None
        return host

    if tool == "web":
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        try:
            host = urlparse(target).hostname or ""
        except Exception:
            host = ""
        if not host or host.startswith(".") or "." not in host:
            log.warning(f"[pipeline] Cannot normalize web target: {target!r}")
            return None
        return target

    return target


def run_pipeline(user_input: str, max_passes: int = 3) -> FindingsStore:
    """
    Run the SecFlow analysis pipeline.

    Args:
        user_input: file path, URL, IP address, or domain name
        max_passes: maximum loop iterations (3, 4, or 5)

    Returns:
        Populated FindingsStore with one entry per completed pass.
    """
    store = FindingsStore()

    # ── Pass 1: Deterministic classification (no AI required) ─────────────────
    log.info(f"[pipeline] Pass 1 — classifying input: {user_input!r}")
    first_analyzer, mime_type, magic_output = classify(user_input)

    if first_analyzer is None:
        # AI fallback: unknown type — ask Gemini to classify
        log.info("[pipeline] Unknown type — using AI fallback for classification")
        file_head = get_file_head(user_input)
        synthetic: dict[str, Any] = {
            "analyzer": "classifier",
            "pass": 0,
            "input": user_input,
            "findings": [],
            "risk_score": 0.0,
            "raw_output": (
                f"MIME: {mime_type}\nmagic: {magic_output}\n"
                f"file head:\n{file_head}"
            ),
        }
        decision = decide_next(synthetic, pass_number=0, max_passes=max_passes, tools_run=[])
        first_analyzer = decision["next_tool"]
        log.info(f"[pipeline] AI chose first analyzer: {first_analyzer} — {decision['reasoning']}")

    if not first_analyzer:
        log.warning("[pipeline] Cannot determine first analyzer — aborting pipeline")
        return store

    # ── Analyzer loop ──────────────────────────────────────────────────────────
    current_tool  = first_analyzer
    current_input = user_input

    # Track executed (tool, target) pairs to avoid infinite loops
    tools_run: list[str] = []
    visited: set[tuple[str, str]] = set()

    for pass_num in range(1, max_passes + 1):
        # Deduplicate — never re-run the exact same (tool, input) pair
        visit_key = (current_tool, str(current_input))
        if visit_key in visited:
            log.warning(f"[pipeline] Skipping duplicate ({current_tool}, {current_input!r})")
            break
        visited.add(visit_key)

        log.info(f"[pipeline] Pass {pass_num}/{max_passes} — {current_tool} on {current_input!r}")

        caller_fn = _CALLER_MAP.get(current_tool)
        if not caller_fn:
            log.error(f"[pipeline] Unknown analyzer: {current_tool!r}")
            break

        try:
            result = caller_fn(current_input, pass_num)
        except Exception as e:
            log.exception(f"[pipeline] Analyzer {current_tool} raised exception: {e}")
            result = {
                "analyzer": current_tool,
                "pass": pass_num,
                "input": current_input,
                "findings": [{"type": "error", "detail": str(e), "severity": "low", "evidence": ""}],
                "risk_score": 0.0,
                "raw_output": str(e),
            }

        store.append(result)
        tools_run.append(current_tool)
        log.info(
            f"[pipeline] Pass {pass_num} done — "
            f"{len(result['findings'])} findings, risk_score={result['risk_score']}"
        )

        if pass_num >= max_passes:
            log.info("[pipeline] Max passes reached — stopping loop")
            break

        # ── AI routing decision ────────────────────────────────────────────────
        decision = decide_next(
            result,
            pass_number=pass_num,
            max_passes=max_passes,
            tools_run=tools_run,
        )
        log.info(
            f"[pipeline] AI decision: next={decision['next_tool']!r} "
            f"target={decision['target']!r} — {decision['reasoning']}"
        )

        if not decision["next_tool"]:
            log.info("[pipeline] AI signalled termination — ending loop early")
            break

        next_input = decision.get("target")
        if not next_input:
            log.warning("[pipeline] AI provided no target — stopping")
            break

        # Normalize target for the specific tool (safety net after AI validation)
        next_input = _normalize_target(decision["next_tool"], next_input)
        if not next_input:
            log.warning(f"[pipeline] Target normalization failed for tool={decision['next_tool']!r} — stopping")
            break

        current_tool  = decision["next_tool"]
        current_input = next_input

    log.info(f"[pipeline] Completed — {len(store.get_all())} pass(es) recorded")
    return store
