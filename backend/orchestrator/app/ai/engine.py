"""
AI Decision Engine — wraps Gemini API to decide the next analyzer in the pipeline loop.

Given the output of the most recent analyzer pass, returns:
  {
    "next_tool": str | None,
    "target":    str | None,   # the exact value to pass to the next analyzer
    "reasoning": str
  }

The engine acts as a SOC analyst: it first extracts concrete artifacts
(URLs, IPs, domains, file paths) from the full raw output, then asks
Gemini — given those artifacts and the analyzer context — which tool to
invoke next and on exactly what target.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from openai import OpenAI

log = logging.getLogger("secflow.ai_engine")

ANALYZER_NAMES = ["malware", "steg", "recon", "web", "macro"]
KEYWORDS_FILE = Path(__file__).parent / "keywords.txt"
MAX_CONTEXT_CHARS = 3000

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        masked = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        log.info(f"[AI] Initializing Groq client — key={masked}")
        _client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    return _client


# ── Artifact extraction (runs on FULL raw_output before Gemini call) ──────────

# Noise domains to filter — glibc stubs, package managers, etc.
_DOMAIN_NOISE = {
    "gnu.org", "github.com", "ubuntu.com", "debian.org", "so.1", "so.2",
    "so.3", "so.6", "glibc.so", "libc.so", "apt.org", "pypi.org",
    "python.org", "localhost", "example.com", "test.com",
}


def _extract_artifacts(text: str) -> dict[str, list[str]]:
    """
    Pre-scan the FULL raw analyzer output (not truncated) for concrete
    IOCs: URLs, IPv4 addresses, domain names.

    Returns deduplicated, capped lists safe to embed in a Gemini prompt.
    """
    # URLs — greedy but stop at obvious terminators
    raw_urls = re.findall(r'https?://[^\s"\'<>\)\(,\\\}]+', text)
    urls: list[str] = list(dict.fromkeys(u.rstrip("/.") for u in raw_urls))

    # IPv4
    raw_ips = re.findall(
        r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        text,
    )
    # re.findall with groups returns tuples — flatten
    ips_flat = re.findall(
        r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b',
        text,
    )
    ips: list[str] = list(dict.fromkeys(ips_flat))

    # Domain-like strings (heuristic: contains a dot, TLD ≥ 2 chars)
    raw_domains = re.findall(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}\b',
        text,
    )
    ip_set = set(ips)
    domains: list[str] = [
        d for d in dict.fromkeys(raw_domains)
        if d not in ip_set
        and d.lower() not in _DOMAIN_NOISE
        and not d.endswith(".so")
        and not d.endswith(".o")
        and "." in d
        and len(d) > 4
    ]

    # Also pull hostnames from found URLs so they appear in the domain list
    for u in urls:
        try:
            host = urlparse(u).hostname or ""
            if host and host not in ip_set and host not in _DOMAIN_NOISE:
                if host not in domains:
                    domains.insert(0, host)
        except Exception:
            pass

    return {
        "urls":    urls[:10],
        "ips":     ips[:5],
        "domains": domains[:10],
    }


_URL_SCHEME_RE = re.compile(r'^https?://')
_VALID_HOST_RE  = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


def _grep_c_strings(text: str) -> str:
    """
    Extract and reconstruct C string literals from Ghidra decompiled output.

    Handles the common binary pattern where a URL is split across several
    adjacent string variables, e.g.:
        char *a = "https://";
        char *b = "aradhyacp.in";
        char *c = "/beacon";
    Step 1 — extract all double-quoted literals (down to 1 char to catch "://")
    Step 2 — stitch consecutive fragments when the running concatenation looks
             like a partial URL, stopping once we have a valid complete URL.
    """
    # Include single-char fragments so we can stitch "https://" + "host" + "/path"
    fragments = re.findall(r'"([^"\n\\]{1,})"', text)

    stitched: list[str] = []
    i = 0
    while i < len(fragments):
        frag = fragments[i]
        # Start stitching when we see a URL scheme opener
        if _URL_SCHEME_RE.match(frag):
            combined = frag
            j = i + 1
            # Keep appending fragments until the URL has a valid hostname
            while j < len(fragments) and len(combined) < 300:
                combined += fragments[j]
                j += 1
                # Stop as soon as we have scheme + valid hostname
                try:
                    parsed = urlparse(combined)
                    if parsed.hostname and _VALID_HOST_RE.match(parsed.hostname):
                        break
                except Exception:
                    pass
            stitched.append(combined)
            i = j
        else:
            # Keep non-scheme fragments as-is for domain/IP extraction
            if len(frag) >= 4:
                stitched.append(frag)
            i += 1

    return "\n".join(stitched)


def _extract_all_artifacts(analyzer_output: dict[str, Any]) -> dict[str, list[str]]:
    """
    Three-layer artifact extraction for maximum IOC coverage:
      1. Standard regex on full raw_output (URLs, IPs, domains)
      2. C string-literal grep — catches domains in Ghidra decompiled C code
      3. Scan findings evidence fields (decompiled[:500], objdump[:500], etc.)

    All results are merged and deduplicated.
    """
    raw_output = analyzer_output.get("raw_output", "")
    findings   = analyzer_output.get("findings", [])

    # Layer 1 — standard artifact extraction on full raw_output
    a1 = _extract_artifacts(raw_output)

    # Layer 2 — C string-literal grep (key for malware/Ghidra output)
    c_strings = _grep_c_strings(raw_output)
    a2 = _extract_artifacts(c_strings) if c_strings.strip() else {"urls": [], "ips": [], "domains": []}

    # Layer 3 — findings evidence fields (often contain first 500 chars of decompiled/objdump)
    evidence_blob = "\n".join(
        str(f.get("evidence", "")) for f in findings if f.get("evidence")
    )
    a3 = _extract_artifacts(evidence_blob) if evidence_blob.strip() else {"urls": [], "ips": [], "domains": []}

    # Merge all three layers, preserving order, deduplicating
    merged: dict[str, list[str]] = {}
    for key, cap in (("urls", 10), ("ips", 5), ("domains", 10)):
        seen = dict.fromkeys(a1[key] + a2[key] + a3[key])
        merged[key] = list(seen)[:cap]

    return merged


def _build_context_excerpt(raw_output: str) -> str:
    """Return a focused excerpt for the Gemini prompt (not the full output)."""
    if len(raw_output) <= MAX_CONTEXT_CHARS:
        return raw_output

    keywords = []
    if KEYWORDS_FILE.exists():
        keywords = [
            ln.strip()
            for ln in KEYWORDS_FILE.read_text().splitlines()
            if ln.strip() and not ln.startswith("#")
        ]

    if keywords:
        matched = [
            ln for ln in raw_output.splitlines()
            if any(kw.lower() in ln.lower() for kw in keywords)
        ]
        if matched:
            return "\n".join(matched)[:MAX_CONTEXT_CHARS]

    return raw_output[:MAX_CONTEXT_CHARS]


def _build_prompt(
    analyzer_output: dict[str, Any],
    pass_number: int,
    max_passes: int,
    artifacts: dict[str, list[str]],
    context_excerpt: str,
    tools_run: list[str],
) -> str:
    current_tool = analyzer_output["analyzer"]
    findings_count = len(analyzer_output.get("findings", []))
    risk_score = analyzer_output.get("risk_score", 0)
    passes_left = max_passes - pass_number

    tools_not_run = [t for t in ANALYZER_NAMES if t not in tools_run]

    return f"""You are a SOC (Security Operations Center) analyst reviewing data from SecFlow, an automated threat analysis pipeline.

### Completed Pass
- Analyzer: **{current_tool}**
- Pass: {pass_number}/{max_passes} ({passes_left} pass(es) remaining)
- Findings: {findings_count}  |  Risk score: {risk_score}/10
- Tools already run this session: {tools_run}
- Tools not yet run: {tools_not_run}

### Extracted Artifacts (from full analyzer output)
```json
{json.dumps(artifacts, indent=2)}
```

### Analyzer Output Excerpt
```
{context_excerpt}
```

### Your Task
As a SOC analyst, decide the single best NEXT analysis step based on the artifacts and findings above.

**Decision rules (evaluate in order):**
1. If URLs were found → `"web"` with the most suspicious/user-facing URL as target
2. If `recon` has NOT run yet and there are IPs or domains → `"recon"` with the most suspicious IP or domain
3. If `recon` just ran on a domain and `web` has NOT run → `"web"` with `"https://<domain>"` as target
4. If `web` just ran on a URL and `recon` has NOT run → `"recon"` with the bare hostname (no https://) as target
5. If an extracted/embedded file path is found → `"malware"` or `"steg"` depending on type
6. If `{current_tool}` found domains/IPs inside decompiled code or data strings / VBA macros → treat as artifacts and apply rules 1-4
7. If `macro` just ran and IOCs contain URLs/IPs/domains → apply rules 1-2 to those IOCs
8. If no passes remain or no new useful artifacts → `null`

**IMPORTANT:**
- `target` must be the **exact string** to pass to the next analyzer (full URL for web, bare domain/IP for recon, file path for malware/steg)
- Never repeat the same (tool, target) pair already in `tools_run`
- Prefer analyzing user-visible external domains over internal library stubs

Respond ONLY with a JSON object — no markdown, no code fences, no extra text:
{{
  "next_tool": "<malware | steg | recon | web | macro | null>",
  "target": "<exact value to analyze, or null if next_tool is null>",
  "reasoning": "<one sentence explaining the decision>"
}}"""


def decide_next(
    analyzer_output: dict[str, Any],
    pass_number: int,
    max_passes: int,
    tools_run: list[str] | None = None,
) -> dict[str, Any]:
    """
    Given the output of the most recent analyzer pass, return the next routing decision.

    Returns:
        {
          "next_tool": str | None,
          "target":    str | None,
          "reasoning": str
        }
    """
    if tools_run is None:
        tools_run = []

    raw_output = analyzer_output.get("raw_output", "")

    # Extract artifacts using all available sources (raw_output + C strings + findings evidence)
    artifacts = _extract_all_artifacts(analyzer_output)
    log.info(
        f"[AI] Artifacts extracted — urls={artifacts['urls']}, "
        f"ips={artifacts['ips']}, domains={artifacts['domains']}"
    )

    # Build a shorter focused excerpt for the prompt
    context = _build_context_excerpt(raw_output)

    prompt = _build_prompt(
        analyzer_output,
        pass_number,
        max_passes,
        artifacts,
        context,
        tools_run,
    )

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model="qwen/qwen3-32b",
            messages=[
                {"role": "system", "content": "/no_think"},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.1,
            max_tokens=512,
        )
        raw_text = (response.choices[0].message.content or "").strip()
        log.debug(f"[AI] Raw Groq response: {raw_text[:300]!r}")

        # Strip any residual <think> blocks and markdown fences
        text = re.sub(r"<think>[\s\S]*?</think>", "", raw_text).strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE).strip()

        if not text:
            log.warning("[AI] Groq response was empty after stripping — falling back to rule-based routing")
            decision = _rule_based_decide(analyzer_output, artifacts, tools_run)
            log.info(f"[AI] Rule-based fallback: next={decision['next_tool']!r} target={decision['target']!r}")
            return decision

        result = json.loads(text)

        next_tool = result.get("next_tool")
        if next_tool not in ANALYZER_NAMES + [None, "null"]:
            log.warning(f"Groq returned unknown tool '{next_tool}' — treating as null")
            next_tool = None
        if next_tool == "null":
            next_tool = None

        target = result.get("target")
        if target == "null" or target == "":
            target = None

        # Validate target — reject malformed AI-hallucinated values (e.g. "https://.in/")
        if target:
            target = _sanitize_target(next_tool, target)

        # If no valid target, fall back to artifact extraction
        if next_tool and not target:
            target = _fallback_target(next_tool, artifacts, analyzer_output)

        return {
            "next_tool": next_tool,
            "target":    target,
            "reasoning": result.get("reasoning", ""),
        }

    except json.JSONDecodeError as e:
        log.error(f"Groq returned non-JSON response: {e} — falling back to rule-based routing")
        decision = _rule_based_decide(analyzer_output, artifacts, tools_run)
        log.info(f"[AI] Rule-based fallback: next={decision['next_tool']!r} target={decision['target']!r}")
        return decision
    except Exception as e:
        log.error(f"AI decision engine error: {e} — falling back to rule-based routing")
        decision = _rule_based_decide(analyzer_output, artifacts, tools_run)
        log.info(f"[AI] Rule-based fallback: next={decision['next_tool']!r} target={decision['target']!r}")
        return decision


def _rule_based_decide(
    analyzer_output: dict[str, Any],
    artifacts: dict[str, list[str]],
    tools_run: list[str],
) -> dict[str, Any]:
    """
    Deterministic rule-based routing when Gemini is unavailable (quota, network, etc.).
    Applies the same decision rules as the SOC analyst prompt, in the same order.
    """
    current_tool = analyzer_output.get("analyzer", "")
    urls    = artifacts.get("urls", [])
    ips     = artifacts.get("ips", [])
    domains = artifacts.get("domains", [])

    # Rule 1: URLs found → web (if not already run)
    if urls and "web" not in tools_run:
        return {
            "next_tool": "web",
            "target":    urls[0],
            "reasoning": "Rule-based fallback: URL found in output → web analyzer",
        }

    # Rule 2: IPs or domains found, recon hasn't run
    if (ips or domains) and "recon" not in tools_run:
        target = ips[0] if ips else domains[0]
        return {
            "next_tool": "recon",
            "target":    target,
            "reasoning": "Rule-based fallback: IP/domain found → recon analyzer",
        }

    # Rule 3: Recon just ran — cross-check with web if not done
    if current_tool == "recon" and "web" not in tools_run:
        recon_input = analyzer_output.get("input", "")
        if recon_input:
            web_target = recon_input if recon_input.startswith("http") else f"https://{recon_input}"
            return {
                "next_tool": "web",
                "target":    web_target,
                "reasoning": "Rule-based fallback: recon completed → web analyzer on same target",
            }
        if domains:
            return {
                "next_tool": "web",
                "target":    f"https://{domains[0]}",
                "reasoning": "Rule-based fallback: recon completed → web on discovered domain",
            }

    # Rule 4: Web just ran — run recon on the hostname if not done
    if current_tool == "web" and "recon" not in tools_run:
        web_input = analyzer_output.get("input", "")
        if web_input:
            try:
                parsed = urlparse(web_input if web_input.startswith("http") else f"https://{web_input}")
                host = parsed.hostname or web_input
                return {
                    "next_tool": "recon",
                    "target":    host,
                    "reasoning": "Rule-based fallback: web completed → recon on hostname",
                }
            except Exception:
                pass
        if domains:
            return {
                "next_tool": "recon",
                "target":    domains[0],
                "reasoning": "Rule-based fallback: web completed → recon on domain",
            }

    # Rule 5: URLs found, web already ran, recon hasn't — recon on URL hostname
    if urls and "web" in tools_run and "recon" not in tools_run:
        try:
            host = urlparse(urls[0]).hostname
            if host:
                return {
                    "next_tool": "recon",
                    "target":    host,
                    "reasoning": "Rule-based fallback: web ran → recon on URL hostname",
                }
        except Exception:
            pass

    return {
        "next_tool": None,
        "target":    None,
        "reasoning": "Rule-based fallback: no new artifacts to analyze",
    }


def _sanitize_target(tool: str | None, target: str) -> str | None:
    """
    Validate and normalise the target returned by the AI.
    Returns None if the target looks malformed so the caller falls back to
    artifact-based extraction.
    """
    if not target or not tool:
        return None

    t = target.strip().rstrip("/")

    if tool == "recon":
        # recon needs a bare IP or domain — strip any scheme/path
        try:
            parsed = urlparse(t if "://" in t else f"https://{t}")
            host = (parsed.hostname or "").strip()
        except Exception:
            host = ""
        # Reject empty hostnames or pure TLD fragments like ".in"
        if not host or host.startswith(".") or "." not in host:
            log.warning(f"[AI] Rejected malformed recon target {target!r}")
            return None
        return host

    if tool == "web":
        # web needs a URL — ensure scheme is present
        if not t.startswith(("http://", "https://")):
            t = f"https://{t}"
        try:
            host = urlparse(t).hostname or ""
        except Exception:
            host = ""
        if not host or host.startswith(".") or "." not in host:
            log.warning(f"[AI] Rejected malformed web target {target!r}")
            return None
        return t

    return target


def _fallback_target(
    next_tool: str,
    artifacts: dict[str, list[str]],
    analyzer_output: dict[str, Any],
) -> str | None:
    """
    Last-resort target extraction when Gemini doesn't return one.
    Uses the pre-extracted artifacts dict.
    """
    if next_tool == "web":
        if artifacts["urls"]:
            return artifacts["urls"][0]
        if artifacts["domains"]:
            return f"https://{artifacts['domains'][0]}"

    if next_tool == "recon":
        if artifacts["ips"]:
            return artifacts["ips"][0]
        if artifacts["domains"]:
            # return bare domain (recon doesn't want https://)
            return artifacts["domains"][0]
        if artifacts["urls"]:
            try:
                return urlparse(artifacts["urls"][0]).hostname
            except Exception:
                pass

    if next_tool in ("malware", "steg"):
        for f in analyzer_output.get("findings", []):
            if f.get("extracted_path"):
                return f["extracted_path"]
        extracted = analyzer_output.get("extracted_files", [])
        if extracted:
            return extracted[0]

    return analyzer_output.get("input")
