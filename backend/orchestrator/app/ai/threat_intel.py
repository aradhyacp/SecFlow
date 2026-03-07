"""
Threat Intelligence Generator — SecFlow AI Module.

Makes three sequential structured calls to llama-3.3-70b-versatile (via Groq) to
produce SOC-ready threat intelligence artifacts from the completed pipeline output:

  Call 1 — Threat Summary
      Structured assessment: threat name, actor type, attack chain, IOC inventory,
      MITRE ATT&CK TTPs, confidence level, and full reasoning narrative.

  Call 2 — YARA Detection Rules
      2–5 YARA rules tailored to the specific indicators and strings found.
      Each rule includes a reasoning field citing the exact evidence that drove it.

  Call 3 — SIGMA Detection Rules
      2–4 SIGMA rules for SIEM/SOC deployment (Splunk, Elastic, Sentinel).
      Each rule targets a distinct log source and includes full reasoning.

Context construction:
  - All findings from every pipeline pass are included.
  - Ghidra decompilation output is capped at MAX_DECOMPILE_LINES (1000) lines.
  - All other evidence is included in full (JSON evidence is pretty-printed).
  - Finding evidence from previous passes is sent verbatim — no truncation
    except for decompile/disassembly code blobs.

All three calls use structured JSON output prompts so the model returns
machine-parseable output consistently throughout the project.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

from openai import OpenAI

log = logging.getLogger("secflow.threat_intel")

_MODEL = "llama-3.3-70b-versatile"
_MAX_DECOMPILE_LINES = 1000  # Ghidra output cap — user-specified

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        _client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    return _client


def _clean_json(text: str) -> str:
    """Strip <think> blocks and markdown code fences from model output."""
    text = re.sub(r"<think>[\s\S]*?</think>", "", text).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text).strip()
    return text


# ── Context builder ────────────────────────────────────────────────────────────

def _build_context(raw_findings: list[dict]) -> str:
    """
    Build a comprehensive, model-readable context string from all pipeline passes.

    Strategy:
    - Every finding from every pass is included: type, severity, detail, evidence.
    - decompilation / disassembly evidence is hard-capped at MAX_DECOMPILE_LINES
      lines so the Ghidra JVM output does not dominate the token budget.
    - All other evidence (VT JSON, IOC lists, recon results, olevba output) is
      included in full — these are typically small and highly signal-dense.
    - JSON evidence blobs are pretty-printed for the model to read more easily.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    parts: list[str] = [
        "SECFLOW AUTOMATED THREAT ANALYSIS — COMPLETE PIPELINE OUTPUT",
        f"Date: {today}",
        "=" * 70,
    ]

    for item in raw_findings:
        analyzer  = item.get("analyzer", "unknown").upper()
        pass_num  = item.get("pass", "?")
        risk      = item.get("risk_score", 0)
        input_val = item.get("input", "")

        parts.append(f"\n{'─' * 60}")
        parts.append(
            f"PASS {pass_num} | {analyzer} ANALYZER | "
            f"Risk Score: {risk}/10 | Target: {input_val}"
        )
        parts.append(f"{'─' * 60}")

        for f in item.get("findings", []):
            ftype    = f.get("type", "unknown")
            severity = (f.get("severity") or "info").upper()
            detail   = f.get("detail", "")

            parts.append(f"\n[{severity}] {ftype}")
            parts.append(f"  Detail: {detail}")

            ev = (f.get("evidence") or "").strip()
            if not ev:
                continue

            # Decompile / disassembly: hard cap at 1000 lines
            if ftype in ("decompilation", "disassembly"):
                lines = ev.split("\n")
                taken = min(len(lines), _MAX_DECOMPILE_LINES)
                ev_out = "\n".join(lines[:taken])
                if len(lines) > taken:
                    ev_out += (
                        f"\n[... {len(lines) - taken} additional lines truncated — "
                        f"Ghidra output capped at {_MAX_DECOMPILE_LINES} lines ...]"
                    )
                parts.append(f"  Code Output (first {taken} lines):\n{ev_out}")
                continue

            # JSON evidence — pretty-print for model readability
            if ev.startswith(("{", "[")):
                try:
                    ev = json.dumps(json.loads(ev), indent=2)
                except (json.JSONDecodeError, ValueError):
                    pass

            parts.append(f"  Evidence:\n{ev}")

    context = "\n".join(parts)
    log.info(
        f"[threat_intel] Context built — {len(raw_findings)} passes, "
        f"{len(context):,} chars"
    )
    return context


# ── Call 1: Threat Summary ─────────────────────────────────────────────────────

# Exact schema the model must return — shown verbatim in the prompt.
_THREAT_SUMMARY_SCHEMA = """{
  "threat_name": "Descriptive name for this specific threat (e.g. 'Macro-delivered AsyncRAT with Tor-based C2')",
  "threat_actor_type": "one of: APT | Cybercrime | Ransomware | Hacktivism | Script Kiddie | Unknown",
  "attack_vector": "Initial access method description",
  "attack_chain": [
    "Step 1: ...",
    "Step 2: ...",
    "Step N: ..."
  ],
  "iocs": {
    "hashes":     ["sha256 or md5 values found in analysis"],
    "ips":        ["malicious or suspicious IP addresses"],
    "domains":    ["malicious or suspicious domains"],
    "urls":       ["full malicious URLs"],
    "file_names": ["suspicious file names or paths"]
  },
  "mitre_ttps": [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"}
  ],
  "severity":   "Critical | High | Medium | Low",
  "confidence": "High | Medium | Low",
  "reasoning":  "2-4 sentence paragraph explaining what was found, why it is classified this way, and any notable characteristics of this threat."
}"""


def _call_threat_summary(context: str) -> dict[str, Any]:
    """
    Call 1/3 — Generate a structured threat intelligence summary.

    Asks the model to:
    - Identify and name the threat
    - Classify the actor type
    - Extract all IOCs from the evidence
    - Map observed behaviors to MITRE ATT&CK TTPs
    - Provide a confidence-rated assessment with full reasoning
    """
    prompt = (
        "You are a Tier-3 SOC analyst at a CSIRT. You have just completed a "
        "multi-stage automated threat analysis. Your job is to produce a structured "
        "threat intelligence summary that will be sent to the security leadership team.\n\n"
        "Analyze the complete pipeline output below and respond ONLY with a single "
        "valid JSON object matching this exact schema — no other text:\n\n"
        f"{_THREAT_SUMMARY_SCHEMA}\n\n"
        "Requirements:\n"
        "- Extract EVERY IOC (IP, domain, URL, hash, filename) visible in the evidence.\n"
        "- Map EVERY identified behavior to a real MITRE ATT&CK TTP (use correct IDs).\n"
        "- If a field has no data, use an empty array [] or empty string \"\".\n"
        "- The reasoning field must be substantive (2-4 sentences minimum).\n"
        "- Do NOT wrap the JSON in markdown code fences.\n\n"
        "Complete Pipeline Analysis Output:\n"
        f"{context}"
    )

    client = _get_client()
    log.info(f"[threat_intel] Call 1/3 — Threat Summary → {_MODEL}")
    resp = client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=2048,
    )
    raw  = resp.choices[0].message.content or ""
    data = json.loads(_clean_json(raw))
    log.info(
        f"[threat_intel] Call 1 complete — threat='{data.get('threat_name', '?')}', "
        f"confidence={data.get('confidence', '?')}"
    )
    return data


# ── Call 2: YARA Rules ──────────────────────────────────────────────────────────

_YARA_SCHEMA = """{
  "reasoning": "Overall explanation of why these YARA rules were generated — which evidence drove them and what threats they collectively defend against.",
  "rules": [
    {
      "rule_name":   "SecFlow_ThreatCategory_IndicatorType",
      "description": "One sentence: what this rule detects",
      "reasoning":   "Why this specific rule — cite the exact evidence from the analysis that informed it (e.g. 'The string xyz was found in the Ghidra decompilation at line 42')",
      "tags":        ["malware", "apt", "relevant-tags"],
      "rule_text":   "rule SecFlow_ThreatCategory_IndicatorType {\\n  meta:\\n    description = \\\"...\\\"\\n    author = \\\"SecFlow AI\\\"\\n    date = \\\"YYYY-MM-DD\\\"\\n    severity = \\\"high\\\"\\n    reference = \\\"SecFlow automated analysis\\\"\\n  strings:\\n    $s1 = \\\"suspicious_string\\\"\\n    $b1 = { DE AD BE EF }\\n  condition:\\n    any of them\\n}"
    }
  ],
  "total_rules": 1
}"""


def _call_yara_rules(context: str, threat_summary: dict) -> dict[str, Any]:
    """
    Call 2/3 — Generate YARA detection rules.

    Uses the threat summary from Call 1 as additional context so the rules
    align with the identified threat actor type, TTPs, and IOC inventory.
    Asks for 2–5 rules each targeting a distinct indicator or behavior.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    threat_ctx = json.dumps(threat_summary, indent=2)

    prompt = (
        "You are an expert malware analyst and detection engineer specializing "
        "in YARA rule authoring. You have a completed threat intelligence summary "
        "and the full pipeline output from an automated security analysis.\n\n"
        "Generate practical YARA rules that a SOC team can deploy immediately to "
        "detect this threat in their file scanning infrastructure, EDR, or sandbox.\n\n"
        "Respond ONLY with a single valid JSON object matching this exact schema — no other text:\n\n"
        f"{_YARA_SCHEMA}\n\n"
        "YARA authoring requirements:\n"
        f"- Use today's date {today} in each rule's meta.date field.\n"
        "- Every rule MUST have valid YARA syntax (compilable with yara-python 4.x).\n"
        "- Use the meta: section: description, author, date, severity, reference.\n"
        "- Base strings/byte patterns on ACTUAL indicators from the analysis output "
        "(do not invent generic strings — use what you found).\n"
        "- Generate 2–5 rules, each targeting a DIFFERENT aspect:\n"
        "  * File signature / magic bytes\n"
        "  * Embedded strings (C2 URLs, mutex names, registry keys)\n"
        "  * VBA macro patterns (if Office documents were analyzed)\n"
        "  * Packed/obfuscated binary indicators\n"
        "  * Network IOC references in memory\n"
        "- Rule names MUST follow: SecFlow_[ThreatCategory]_[IndicatorType]\n"
        "- The 'reasoning' for each rule MUST cite the exact line/evidence from the analysis.\n"
        "- Do NOT wrap the JSON in markdown code fences.\n\n"
        f"Threat Intelligence Summary (from prior analysis):\n{threat_ctx}\n\n"
        f"Complete Pipeline Analysis Output:\n{context}"
    )

    client = _get_client()
    log.info(f"[threat_intel] Call 2/3 — YARA Rules → {_MODEL}")
    resp = client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=3072,
    )
    raw  = resp.choices[0].message.content or ""
    data = json.loads(_clean_json(raw))
    log.info(
        f"[threat_intel] Call 2 complete — "
        f"{data.get('total_rules', len(data.get('rules', [])))} YARA rules"
    )
    # Normalise total_rules in case model forgot to set it
    data.setdefault("total_rules", len(data.get("rules", [])))
    return data


# ── Call 3: SIGMA Rules ─────────────────────────────────────────────────────────

_SIGMA_SCHEMA = """{
  "reasoning": "Overall explanation of why these SIGMA rules were generated — which log sources they cover and what SOC use-cases they address.",
  "rules": [
    {
      "rule_name":   "detect_threat_behavior_lowercase_underscores",
      "description": "One sentence: what log activity this rule detects",
      "log_source":  "Windows Security | Sysmon | Web Proxy | EDR | DNS | Network | Email",
      "reasoning":   "Why this specific rule — cite the observed behavior from the analysis that necessitates this log source and detection logic",
      "rule_text":   "title: Detect Suspicious Behavior\\nid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\\nstatus: experimental\\ndescription: Detects ...\\nauthor: SecFlow AI\\ndate: YYYY/MM/DD\\nmodified: YYYY/MM/DD\\ntags:\\n  - attack.execution\\n  - attack.t1059\\nlogsource:\\n  category: process_creation\\n  product: windows\\ndetection:\\n  selection:\\n    CommandLine|contains:\\n      - 'suspicious_string'\\n  condition: selection\\nfalsepositives:\\n  - Legitimate administrative scripts\\nlevel: high"
    }
  ],
  "total_rules": 1
}"""


def _call_sigma_rules(context: str, threat_summary: dict) -> dict[str, Any]:
    """
    Call 3/3 — Generate SIGMA detection rules for SIEM deployment.

    Uses the threat summary from Call 1 as context to ensure the SIGMA rules
    map to exactly the observed TTPs and can be imported into any SIGMA-compatible
    SIEM (Splunk, Elastic Security, Microsoft Sentinel, Chronicle, QRadar).
    """
    today_sigma = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    threat_ctx  = json.dumps(threat_summary, indent=2)

    prompt = (
        "You are an expert SIEM detection engineer specializing in SIGMA rule "
        "authoring for enterprise SOC teams. You have a completed threat intelligence "
        "summary and the full pipeline output from an automated security analysis.\n\n"
        "Generate practical SIGMA rules that a SOC team can immediately import into "
        "Splunk, Elastic Security, Microsoft Sentinel, or any SIGMA-compatible SIEM.\n\n"
        "Respond ONLY with a single valid JSON object matching this exact schema — no other text:\n\n"
        f"{_SIGMA_SCHEMA}\n\n"
        "SIGMA authoring requirements:\n"
        f"- Use today's date {today_sigma} in each rule's date and modified fields.\n"
        "- Every rule MUST have valid SIGMA syntax (compatible with sigma-cli 0.x and pySigma).\n"
        "- Include a valid UUID v4 in the 'id' field of each rule (generate a random one).\n"
        "- Use appropriate logsource categories:\n"
        "  * process_creation — command execution, suspicious child processes\n"
        "  * network_connection — outbound C2 traffic, suspicious IPs/domains\n"
        "  * file_event — dropper activity, suspicious file writes\n"
        "  * dns_query — malicious domain lookups\n"
        "  * registry_event — persistence mechanisms\n"
        "  * web — web proxy/WAF logs for URL-based threats\n"
        "- Generate 2–4 rules, each covering a DIFFERENT log source.\n"
        "- Tags MUST map to real MITRE ATT&CK tactics/techniques from the threat summary.\n"
        "- The 'reasoning' for each rule MUST cite the specific observed behavior.\n"
        "- Set appropriate levels: critical | high | medium | low.\n"
        "- Rule names must be lowercase with underscores.\n"
        "- Do NOT wrap the JSON in markdown code fences.\n\n"
        f"Threat Intelligence Summary (from prior analysis):\n{threat_ctx}\n\n"
        f"Complete Pipeline Analysis Output:\n{context}"
    )

    client = _get_client()
    log.info(f"[threat_intel] Call 3/3 — SIGMA Rules → {_MODEL}")
    resp = client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=3072,
    )
    raw  = resp.choices[0].message.content or ""
    data = json.loads(_clean_json(raw))
    log.info(
        f"[threat_intel] Call 3 complete — "
        f"{data.get('total_rules', len(data.get('rules', [])))} SIGMA rules"
    )
    data.setdefault("total_rules", len(data.get("rules", [])))
    return data


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_threat_intel(raw_findings: list[dict]) -> dict[str, Any]:
    """
    Run three sequential AI calls to produce SOC-ready threat intelligence.

    This function must be called AFTER all pipeline passes complete so the
    model receives the full context from every analyzer.

    Args:
        raw_findings: list of SecFlow contract dicts from the Findings Store.

    Returns:
        {
            "model":          str,   # "llama-3.3-70b-versatile"
            "threat_summary": dict,  # Call 1 — threat name, TTPs, IOCs, reasoning
            "yara":           dict,  # Call 2 — rules[], total_rules, reasoning
            "sigma":          dict,  # Call 3 — rules[], total_rules, reasoning
            "error":          str | None,
        }
    """
    result: dict[str, Any] = {
        "model":          _MODEL,
        "threat_summary": {},
        "yara":           {"rules": [], "total_rules": 0, "reasoning": ""},
        "sigma":          {"rules": [], "total_rules": 0, "reasoning": ""},
        "error":          None,
    }

    context = _build_context(raw_findings)

    # ── Call 1: Threat Summary ─────────────────────────────────────────────────
    try:
        result["threat_summary"] = _call_threat_summary(context)
    except Exception as exc:
        log.warning(f"[threat_intel] Call 1 (threat summary) failed: {exc}")
        result["threat_summary"] = {
            "threat_name":      "Analysis Unavailable",
            "threat_actor_type": "Unknown",
            "attack_vector":    "",
            "attack_chain":     [],
            "iocs":             {"hashes": [], "ips": [], "domains": [], "urls": [], "file_names": []},
            "mitre_ttps":       [],
            "severity":         "Unknown",
            "confidence":       "Low",
            "reasoning":        f"AI call failed: {exc}",
        }
        result["error"] = f"threat_summary: {exc}"

    # ── Call 2: YARA Rules ─────────────────────────────────────────────────────
    try:
        result["yara"] = _call_yara_rules(context, result["threat_summary"])
    except Exception as exc:
        log.warning(f"[threat_intel] Call 2 (YARA) failed: {exc}")
        result["yara"] = {
            "rules":       [],
            "total_rules": 0,
            "reasoning":   f"YARA generation failed: {exc}",
        }
        result["error"] = (result["error"] or "") + f" | yara: {exc}"

    # ── Call 3: SIGMA Rules ────────────────────────────────────────────────────
    try:
        result["sigma"] = _call_sigma_rules(context, result["threat_summary"])
    except Exception as exc:
        log.warning(f"[threat_intel] Call 3 (SIGMA) failed: {exc}")
        result["sigma"] = {
            "rules":       [],
            "total_rules": 0,
            "reasoning":   f"SIGMA generation failed: {exc}",
        }
        result["error"] = (result["error"] or "") + f" | sigma: {exc}"

    n_yara  = result["yara"].get("total_rules", 0)
    n_sigma = result["sigma"].get("total_rules", 0)
    log.info(
        f"[threat_intel] Complete — {n_yara} YARA rule(s), "
        f"{n_sigma} SIGMA rule(s), model={_MODEL}"
    )
    return result
