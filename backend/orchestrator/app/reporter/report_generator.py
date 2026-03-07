"""
Report Generator — SecFlow PWNDoc-style threat report.

Architecture (new):
  1. _build_base_report()  — always succeeds, source-of-truth for all evidence
  2. _ask_groq_to_enhance()— AI writes summary + recommendations ONLY (fits in token budget)
  3. generate_report()     — merges both, renders JSON + HTML

HTML is generated as a plain Python string (no Jinja2).
Evidence types are rendered intelligently:
  - VT stats JSON      → key-value table with colour-coded rows
  - AV detection JSON  → severity badge + result name
  - decompilation      → collapsible <details> + dark <pre> code block (full, uncapped)
  - disassembly        → collapsible <details> + dark <pre> code block (full, uncapped)
  - generic JSON       → key-value table
  - long plain text    → collapsible <details>
  - short text         → inline <code> chip
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from html import escape as he
from pathlib import Path
from typing import Any

from openai import OpenAI
from jsonschema import validate, ValidationError

log = logging.getLogger("secflow.reporter")

SCHEMA_PATH = Path(__file__).parent / "pwndoc_schema.json"

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        masked = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "***"
        log.info(f"[reporter] Initializing Groq client — key={masked}")
        _client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    return _client


# ── Severity helpers ───────────────────────────────────────────────────────────

_SEV_COLORS: dict[str, tuple[str, str]] = {
    "critical": ("#fee2e2", "#991b1b"),
    "high":     ("#fff7ed", "#9a3412"),
    "medium":   ("#fffbeb", "#92400e"),
    "low":      ("#f0fdf4", "#166534"),
    "info":     ("#eff6ff", "#1e40af"),
    "error":    ("#fff1f2", "#881337"),
}

_ANALYZER_ICONS: dict[str, str] = {
    "malware": "🦠", "steg": "🖼️", "recon": "🔍",
    "web": "🌐", "url": "🔗", "classifier": "🗂️",
}

_ANALYZER_LABELS: dict[str, str] = {
    "malware": "Malware Analysis",
    "steg":    "Steganography Analysis",
    "recon":   "Reconnaissance",
    "web":     "Web Vulnerability Analysis",
    "url":     "URL Analysis",
}


def _risk_meta(score: float) -> tuple[str, str, str]:
    """Return (css_class, label, hex_color)."""
    if score >= 8.0: return "critical", "Critical Risk", "#dc2626"
    if score >= 6.0: return "high",     "High Risk",     "#ea580c"
    if score >= 4.0: return "medium",   "Medium Risk",   "#d97706"
    if score >= 2.0: return "low",      "Low Risk",      "#16a34a"
    return "info", "Informational", "#2563eb"


# ── Evidence rendering ─────────────────────────────────────────────────────────

def _ev_kv_table(data: dict) -> str:
    rows = ""
    for k, v in data.items():
        v_str = str(v)
        style = ""
        if k in ("malicious", "suspicious") and v not in (0, "0", None):
            style = ' style="color:#dc2626;font-weight:700"'
        elif k == "undetected" and isinstance(v, int) and v > 0:
            style = ' style="color:#16a34a"'
        rows += (
            f'<tr>'
            f'<td class="ev-k">{he(str(k))}</td>'
            f'<td class="ev-v"{style}>{he(v_str)}</td>'
            f'</tr>'
        )
    return f'<table class="ev-table"><tbody>{rows}</tbody></table>'


def _ev_code_block(code: str, label: str, lang: str = "") -> str:
    lines = code.count("\n") + 1
    return (
        f'<details class="ev-det">'
        f'<summary class="ev-sum">&#9654; {he(label)} '
        f'<span class="ev-meta">({lines:,} lines, {len(code):,} chars)</span></summary>'
        f'<pre class="ev-code lang-{lang}">{he(code)}</pre>'
        f'</details>'
    )


def _render_evidence(finding: dict) -> str:
    """Return pre-rendered HTML for a finding's evidence field."""
    ftype = finding.get("type", "")
    ev = (finding.get("evidence") or "").strip()
    if not ev:
        return ""

    # VT stats / clean result → key-value table
    if ftype in ("malware_detection", "malware_clean") and ev.startswith("{"):
        try:
            stats = json.loads(ev)
            if isinstance(stats, dict):
                return _ev_kv_table(stats)
        except (json.JSONDecodeError, ValueError):
            pass

    # AV engine detection → badge + result name
    if ftype == "av_detection" and ev.startswith("{"):
        try:
            data = json.loads(ev)
            if isinstance(data, dict):
                cat = (data.get("category") or "").lower()
                result = data.get("result") or data.get("engine_name") or "detected"
                bg, fg = _SEV_COLORS.get("high" if cat == "malicious" else "medium",
                                          _SEV_COLORS["info"])
                return (
                    f'<span style="background:{bg};color:{fg};padding:2px 8px;'
                    f'border-radius:4px;font-size:0.72rem;font-weight:700">'
                    f'{he(cat.upper() or "DETECTED")}</span> '
                    f'<code class="ev-chip">{he(str(result))}</code>'
                )
        except (json.JSONDecodeError, ValueError):
            pass

    # Ghidra decompiled C code → full collapsible code block
    if ftype == "decompilation":
        return _ev_code_block(ev, "Decompiled C Code", "c")

    # objdump disassembly → full collapsible code block
    if ftype == "disassembly":
        return _ev_code_block(ev, "Assembly / objdump -d", "asm")

    # Generic JSON object → key-value table
    if ev.startswith("{"):
        try:
            data = json.loads(ev)
            if isinstance(data, dict):
                return _ev_kv_table(data)
        except (json.JSONDecodeError, ValueError):
            pass

    # Long plain text → collapsible
    if len(ev) > 400:
        return _ev_code_block(ev, "View Evidence", "")

    # Short text → inline chip
    return f'<code class="ev-chip">{he(ev)}</code>'


# ── CSS ────────────────────────────────────────────────────────────────────────

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
  background: #f3f4f6; color: #1e293b; font-size: 14px; line-height: 1.6;
}
code { font-family: "SFMono-Regular","Cascadia Code",Consolas,Menlo,monospace; }
a { color: #1d4ed8; text-decoration: none; }

/* Header */
.hdr {
  background: linear-gradient(160deg, #0d1b2a 0%, #1a3a5c 100%);
  color: white; border-bottom: 4px solid #1d4ed8;
}
.hdr-inner {
  max-width: 1080px; margin: 0 auto; padding: 1.8rem 1.5rem;
  display: flex; justify-content: space-between; align-items: flex-start;
  flex-wrap: wrap; gap: 1rem;
}
.hdr-brand { display: flex; align-items: center; gap: 0.75rem; }
.hdr-logo  { font-size: 2.1rem; line-height: 1; }
.hdr-title { font-size: 1.55rem; font-weight: 800; letter-spacing: 0.3px; }
.hdr-sub   { font-size: 0.7rem; color: rgba(255,255,255,.45); margin-top: 0.15rem; }
.hdr-right { text-align: right; }
.hdr-target {
  font-family: monospace;
  background: rgba(255,255,255,.1); border: 1px solid rgba(255,255,255,.2);
  border-radius: 5px; padding: 0.3rem 0.75rem; font-size: 0.82rem;
  display: inline-block; word-break: break-all; max-width: 400px;
}
.hdr-date  { font-size: 0.68rem; color: rgba(255,255,255,.4); margin-top: 0.35rem; }
.hdr-badge {
  display: inline-block; margin-top: 0.45rem;
  padding: 0.2rem 0.7rem; border-radius: 20px;
  font-size: 0.68rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.5px;
}

/* Page layout */
.page { max-width: 1080px; margin: 0 auto; padding: 1.8rem 1.5rem 4rem; }
section { margin-bottom: 2.5rem; }

/* Section heading */
.sec-head {
  font-size: 0.72rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.7px; color: #64748b;
  border-bottom: 2px solid #e2e8f0; padding-bottom: 0.45rem;
  margin-bottom: 1.1rem;
}

/* Metric cards */
.cards {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 0.9rem; margin-bottom: 2rem;
}
.card {
  background: white; border-radius: 8px; padding: 1rem 1.2rem;
  box-shadow: 0 1px 4px rgba(0,0,0,.08); border-left: 4px solid #cbd5e1;
}
.card-lbl { font-size: 0.64rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; color: #94a3b8; }
.card-val { font-size: 1.9rem; font-weight: 800; line-height: 1.1; margin-top: 0.15rem; }
.card-sub { font-size: 0.68rem; color: #94a3b8; margin-top: 0.1rem; }

/* Summary */
.summary-box {
  background: white; border-radius: 8px; padding: 1.2rem 1.4rem;
  box-shadow: 0 1px 4px rgba(0,0,0,.07);
  color: #374151; font-size: 0.88rem; line-height: 1.75;
  border-left: 4px solid #1d4ed8;
}

/* Pass block */
.pass-block {
  background: white; border-radius: 8px; overflow: hidden;
  box-shadow: 0 1px 4px rgba(0,0,0,.07); margin-bottom: 1.1rem;
}
.pass-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0.75rem 1.15rem;
  background: #0d1b2a; color: white; flex-wrap: wrap; gap: 0.5rem;
}
.pass-left  { display: flex; align-items: center; gap: 0.55rem; }
.pass-badge {
  background: rgba(255,255,255,.15); border-radius: 50%;
  width: 22px; height: 22px; display: inline-flex; align-items: center;
  justify-content: center; font-size: 0.68rem; font-weight: 700;
}
.pass-name  { font-size: 0.86rem; font-weight: 700; }
.pass-tag {
  background: rgba(255,255,255,.1); border: 1px solid rgba(255,255,255,.2);
  border-radius: 3px; padding: 0.08rem 0.4rem;
  font-size: 0.62rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px;
}
.pass-input {
  font-family: monospace; font-size: 0.68rem; color: rgba(255,255,255,.45);
  max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.pass-right { font-size: 0.68rem; color: rgba(255,255,255,.45); display: flex; align-items: center; gap: 0.6rem; }
.pass-risk  { background: rgba(255,255,255,.08); border-radius: 4px; padding: 0.08rem 0.45rem; }

/* Findings table */
.ftbl { width: 100%; border-collapse: collapse; }
.ftbl th {
  text-align: left; font-size: 0.62rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.5px; color: #94a3b8;
  padding: 0.55rem 1rem; background: #f8fafc; border-bottom: 1px solid #e2e8f0;
}
.ftbl td { padding: 0.8rem 1rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
.ftbl tr:last-child td { border-bottom: none; }
.ftbl tr:hover td { background: #fafbfd; }
.td-id  { width: 58px; color: #94a3b8; font-size: 0.72rem; font-family: monospace; white-space: nowrap; }
.td-sev { width: 78px; }
.td-typ { width: 130px; color: #64748b; font-size: 0.72rem; word-break: break-word; }
.no-findings { padding: 1rem 1.1rem; color: #94a3b8; font-style: italic; font-size: 0.82rem; }

/* Severity badges */
.sev {
  display: inline-block; padding: 0.17rem 0.48rem; border-radius: 4px;
  font-size: 0.63rem; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.4px; white-space: nowrap;
}
.sev-critical { background:#fee2e2; color:#991b1b; }
.sev-high     { background:#fff7ed; color:#9a3412; }
.sev-medium   { background:#fffbeb; color:#92400e; }
.sev-low      { background:#f0fdf4; color:#166534; }
.sev-info     { background:#eff6ff; color:#1e40af; }
.sev-error    { background:#fff1f2; color:#881337; }

/* Finding content */
.find-detail { color: #1e293b; font-size: 0.84rem; line-height: 1.5; }
.find-ev     { margin-top: 0.5rem; }
.ev-chip {
  background: #f1f5f9; color: #475569;
  padding: 0.13rem 0.38rem; border-radius: 3px;
  font-size: 0.77rem; word-break: break-all;
}

/* Evidence table */
.ev-table  { border-collapse: collapse; font-size: 0.77rem; margin-top: 0.35rem; max-width: 440px; }
.ev-table td { padding: 0.22rem 0.48rem; border: 1px solid #e2e8f0; }
.ev-k { background: #f8fafc; color: #64748b; font-weight: 600; white-space: nowrap; }
.ev-v { font-family: monospace; word-break: break-all; }

/* Collapsible code / text */
.ev-det  { margin-top: 0.45rem; }
.ev-sum  {
  cursor: pointer; font-size: 0.76rem; font-weight: 600; color: #1d4ed8;
  padding: 0.25rem 0; list-style: none; user-select: none;
  display: block;
}
.ev-sum::-webkit-details-marker { display: none; }
details[open] > .ev-sum { color: #1e40af; }
.ev-meta { color: #94a3b8; font-weight: 400; font-size: 0.7rem; }
.ev-code {
  margin-top: 0.4rem;
  background: #0d1b2a; color: #e2e8f0;
  padding: 0.9rem 1.1rem; border-radius: 6px;
  font-family: "SFMono-Regular",Consolas,Menlo,monospace;
  font-size: 0.74rem; line-height: 1.55;
  overflow-x: auto; white-space: pre;
  max-height: 540px; overflow-y: auto;
  border: 1px solid #1e3a5c;
}

/* Recommendations */
.rec-list { background: white; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.07); overflow: hidden; }
.rec-item { display: flex; gap: 0.9rem; padding: 0.95rem 1.1rem; border-bottom: 1px solid #f1f5f9; align-items: flex-start; }
.rec-item:last-child { border-bottom: none; }
.rec-num {
  background: #1d4ed8; color: white; border-radius: 50%;
  width: 22px; height: 22px; min-width: 22px;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.67rem; font-weight: 700; margin-top: 0.15rem;
}
.rec-text { font-size: 0.85rem; color: #374151; line-height: 1.6; }

/* Footer */
.footer {
  text-align: center; padding: 1.1rem;
  font-size: 0.7rem; color: #94a3b8;
  background: white; border-top: 1px solid #e2e8f0; margin-top: 1.5rem;
}
.footer code { background: #f1f5f9; padding: 0.1rem 0.3rem; border-radius: 3px; }

/* Print */
@media print {
  body { background: white; }
  .hdr    { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .pass-head { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  details { open: true; }
  details > summary { display: none; }
  .ev-code { max-height: none; overflow: visible; }
}
@media (max-width: 680px) {
  .cards { grid-template-columns: 1fr 1fr; }
  .pass-input { display: none; }
}
"""


# ── HTML assembly ──────────────────────────────────────────────────────────────

def _finding_rows(findings: list[dict], pass_num: int) -> str:
    if not findings:
        return (
            '<tr><td colspan="4" class="no-findings">'
            'No findings recorded for this pass.</td></tr>'
        )
    rows = ""
    for i, f in enumerate(findings, 1):
        sev   = he((f.get("severity") or "info").lower())
        ftype = he((f.get("type") or "").replace("_", " "))
        det   = he(f.get("detail") or "")
        fid   = f"SF-{pass_num:02d}{i:02d}"
        ev_html = _render_evidence(f)
        ev_block = f'<div class="find-ev">{ev_html}</div>' if ev_html else ""
        rows += (
            f'<tr>'
            f'<td class="td-id">{he(fid)}</td>'
            f'<td class="td-sev"><span class="sev sev-{sev}">{sev}</span></td>'
            f'<td class="td-typ">{ftype}</td>'
            f'<td><div class="find-detail">{det}</div>{ev_block}</td>'
            f'</tr>'
        )
    return rows


def _pass_section(p: dict, raw: dict | None) -> str:
    """Render one pass block.  Uses raw findings for evidence when available."""
    pnum     = p.get("pass_number", p.get("pass", 1))
    analyzer = (p.get("analyzer") or "unknown").lower()
    icon     = _ANALYZER_ICONS.get(analyzer, "🔧")
    label    = _ANALYZER_LABELS.get(analyzer, analyzer.title())

    # Merge evidence: prefer the longer raw evidence over AI-reformatted version
    findings = list(p.get("findings", []))
    if raw:
        raw_list = raw.get("findings", [])
        merged = []
        for idx, f in enumerate(findings):
            rf = raw_list[idx] if idx < len(raw_list) else {}
            m  = {**rf, **f}
            raw_ev = rf.get("evidence", "")
            ai_ev  = f.get("evidence", "")
            if raw_ev and (not ai_ev or len(raw_ev) > len(ai_ev)):
                m["evidence"] = raw_ev
            merged.append(m)
        findings = merged

    input_str  = (raw or p).get("input", "")
    risk_score = float((raw or p).get("risk_score", 0))
    rc, _, rc_hex = _risk_meta(risk_score)

    risk_color = "#f87171" if rc in ("critical", "high") else "#86efac"
    input_chip = (
        f'<span class="pass-input">{he(input_str)}</span>'
        if input_str else ""
    )
    rows = _finding_rows(findings, int(pnum) if str(pnum).isdigit() else 0)

    return f"""
<div class="pass-block">
  <div class="pass-head">
    <div class="pass-left">
      <span class="pass-badge">{he(str(pnum))}</span>
      <span style="font-size:1rem">{icon}</span>
      <span class="pass-name">{he(label)}</span>
      <span class="pass-tag">{he(analyzer.upper())}</span>
      {input_chip}
    </div>
    <div class="pass-right">
      <span class="pass-risk">
        Risk: <strong style="color:{risk_color}">{risk_score}/10</strong>
      </span>
      <span>{len(findings)} finding{'s' if len(findings) != 1 else ''}</span>
    </div>
  </div>
  <table class="ftbl">
    <thead>
      <tr><th>ID</th><th>Severity</th><th>Type</th><th>Finding &amp; Evidence</th></tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""


def _render_html(report_data: dict, raw_findings: list[dict], job_id: str) -> str:
    now    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    target = report_data.get("input", "Unknown")
    score  = float(report_data.get("overall_risk_score", 0))
    rc, rl, rc_hex = _risk_meta(score)

    total_findings = sum(
        len(p.get("findings", [])) for p in report_data.get("passes", [])
    )
    crit_high = sum(
        1
        for p in report_data.get("passes", [])
        for f in p.get("findings", [])
        if (f.get("severity") or "").lower() in ("critical", "high")
    )

    # Metric cards
    card_acc = rc_hex
    ch_color = "#dc2626" if crit_high > 0 else "#16a34a"
    cards = f"""
<div class="cards">
  <div class="card" style="border-left-color:{card_acc}">
    <div class="card-lbl">Overall Risk</div>
    <div class="card-val" style="color:{card_acc}">{score}<span style="font-size:1rem;font-weight:400;color:#94a3b8">/10</span></div>
    <div class="card-sub">{rl}</div>
  </div>
  <div class="card" style="border-left-color:#6366f1">
    <div class="card-lbl">Passes Run</div>
    <div class="card-val" style="color:#6366f1">{report_data.get("total_passes",0)}</div>
    <div class="card-sub">Analysis passes completed</div>
  </div>
  <div class="card" style="border-left-color:#0891b2">
    <div class="card-lbl">Total Findings</div>
    <div class="card-val" style="color:#0891b2">{total_findings}</div>
    <div class="card-sub">Across all passes</div>
  </div>
  <div class="card" style="border-left-color:{ch_color}">
    <div class="card-lbl">Critical / High</div>
    <div class="card-val" style="color:{ch_color}">{crit_high}</div>
    <div class="card-sub">High-severity findings</div>
  </div>
</div>"""

    # Pass sections — match AI passes to raw passes by pass number
    raw_map = {r.get("pass", i + 1): r for i, r in enumerate(raw_findings)}
    passes_html = ""
    for p in report_data.get("passes", []):
        pnum = p.get("pass_number", p.get("pass", 1))
        passes_html += _pass_section(p, raw_map.get(pnum))

    # Recommendations
    recs = report_data.get("recommendations") or []
    if recs:
        items = "\n".join(
            f'<div class="rec-item">'
            f'<div class="rec-num">{i}</div>'
            f'<div class="rec-text">{he(str(r))}</div>'
            f'</div>'
            for i, r in enumerate(recs, 1)
        )
        rec_section = f"""
<section>
  <div class="sec-head">Recommendations</div>
  <div class="rec-list">{items}</div>
</section>"""
    else:
        rec_section = ""

    summary = he(report_data.get("summary") or "No summary available.")
    total_p = report_data.get("total_passes", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecFlow Report &mdash; {he(target)}</title>
  <style>{_CSS}</style>
</head>
<body>

<header class="hdr">
  <div class="hdr-inner">
    <div class="hdr-brand">
      <span class="hdr-logo">&#x1F6E1;</span>
      <div>
        <div class="hdr-title">SecFlow</div>
        <div class="hdr-sub">Automated Threat Analysis Report</div>
      </div>
    </div>
    <div class="hdr-right">
      <div class="hdr-target">{he(target)}</div>
      <div class="hdr-date">
        Generated {now} &bull;
        <code style="color:rgba(255,255,255,.4);font-size:0.67rem">{he(job_id)}</code>
      </div>
      <span class="hdr-badge"
            style="background:{rc_hex}22;color:{rc_hex};border:1px solid {rc_hex}44">
        {rl}
      </span>
    </div>
  </div>
</header>

<div class="page">
  {cards}

  <section>
    <div class="sec-head">Executive Summary</div>
    <div class="summary-box">{summary}</div>
  </section>

  <section>
    <div class="sec-head">
      Findings &mdash; {total_p} Pass{'es' if total_p != 1 else ''}
    </div>
    {passes_html}
  </section>

  {rec_section}
</div>

<footer class="footer">
  SecFlow Automated Threat Analysis &mdash; Report ID: <code>{he(job_id)}</code>
</footer>
</body>
</html>"""


# ── Report data builders ───────────────────────────────────────────────────────

def _build_base_report(findings: list[dict]) -> dict[str, Any]:
    """
    Build a complete report dict directly from raw FindingsStore entries.
    This is the source of truth — ALL evidence is preserved, nothing truncated.
    """
    passes = []
    for i, item in enumerate(findings):
        passes.append({
            "pass_number": item.get("pass", i + 1),
            "analyzer":    item.get("analyzer", "unknown"),
            "findings":    item.get("findings", []),
        })

    overall_risk = max((float(f.get("risk_score", 0)) for f in findings), default=0.0)
    input_val    = findings[0].get("input", "unknown") if findings else "unknown"

    return {
        "input":             input_val,
        "total_passes":      len(findings),
        "overall_risk_score": overall_risk,
        "summary":           "Automated analysis completed.",
        "passes":            passes,
        "recommendations":   [],
    }


def _ask_groq_to_enhance(findings: list[dict]) -> dict[str, Any]:
    """
    Ask Groq for a summary and recommendations ONLY.
    We build a compact summary (no full evidence text) to stay within token limits.
    """
    # Compact summary: pass, analyzer, finding types + details (no large evidence blobs)
    compact: list[dict] = []
    for item in findings:
        compact.append({
            "pass":       item.get("pass"),
            "analyzer":   item.get("analyzer"),
            "risk_score": item.get("risk_score"),
            "findings": [
                {
                    "type":     f.get("type"),
                    "detail":   f.get("detail"),
                    "severity": f.get("severity"),
                }
                for f in item.get("findings", [])
            ],
        })

    prompt = (
        "You are a senior security analyst.\n"
        "Review this threat analysis and respond ONLY with JSON:\n"
        '{"summary": "2-3 sentence executive summary", '
        '"recommendations": ["specific actionable recommendation", ...]}\n\n'
        "Findings:\n"
        + json.dumps(compact, indent=2)
    )

    client = _get_client()
    resp = client.chat.completions.create(
        model="qwen/qwen3-32b",
        messages=[
            {"role": "system", "content": "/no_think"},
            {"role": "user",   "content": prompt},
        ],
        temperature=0.2,
        max_tokens=1024,
    )
    raw = (resp.choices[0].message.content or "").strip()
    text = re.sub(r"<think>[\s\S]*?</think>", "", raw).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$",           "", text).strip()
    return json.loads(text)


def _validate_report(report_data: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text())
    validate(instance=report_data, schema=schema)


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_report(
    findings_json: str,
    job_id: str,
    output_dir: str = "/app/reports",
    base_name: str  = "report",
) -> dict[str, str]:
    """
    Generate JSON and HTML reports from FindingsStore JSON.

    Args:
        findings_json: serialized list from FindingsStore.to_json()
        job_id:        SHA-256 hex digest of the target (used as report ID)
        output_dir:    directory to write report files into
        base_name:     filename stem (default "report")

    Returns:
        {"json": path_str, "html": path_str}
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    raw_findings: list[dict] = json.loads(findings_json)

    # Step 1: build base report from raw findings (full evidence preserved)
    report_data = _build_base_report(raw_findings)

    # Step 2: enhance with AI summary + recommendations (small, targeted output)
    try:
        enhancements = _ask_groq_to_enhance(raw_findings)
        if enhancements.get("summary"):
            report_data["summary"] = enhancements["summary"]
        if enhancements.get("recommendations"):
            report_data["recommendations"] = enhancements["recommendations"]
    except Exception as exc:
        log.warning(f"[reporter] AI enhancement failed, using defaults: {exc}")

    # Step 3: optional schema validation (informational only)
    try:
        _validate_report(report_data)
    except ValidationError as exc:
        log.warning(f"[reporter] Schema validation: {exc.message}")

    # Step 4: write JSON (includes full evidence from raw findings)
    json_path = out / f"{base_name}.json"
    json_path.write_text(json.dumps(report_data, indent=2))

    # Step 5: write HTML (evidence rendered intelligently by type)
    html_path = out / f"{base_name}.html"
    html_path.write_text(_render_html(report_data, raw_findings, job_id))

    log.info(f"[reporter] Report written → {output_dir}/{base_name}.{{json,html}}")
    return {"json": str(json_path), "html": str(html_path)}

