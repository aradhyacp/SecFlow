"""
Report Generator — takes the full Findings Store and produces a PWNDoc report.

Uses Gemini AI to format findings into a structured report, then renders:
  - JSON  (structured report data)
  - HTML  (human-readable, styled)
  - PDF   (via fpdf2)

Validates Gemini output against pwndoc_schema.json before writing files.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

from fpdf import FPDF
from google import genai
from google.genai import types
from jinja2 import Template
from jsonschema import validate, ValidationError

log = logging.getLogger("secflow.reporter")

SCHEMA_PATH = Path(__file__).parent / "pwndoc_schema.json"

_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable is not set")
        _client = genai.Client(api_key=api_key)
    return _client


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecFlow Threat Report</title>
  <style>
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; max-width: 960px; margin: 0 auto; }
    h1 { color: #f85149; border-bottom: 2px solid #30363d; padding-bottom: .5rem; }
    h2 { color: #ffa657; margin-top: 2rem; }
    h3 { color: #79c0ff; }
    .meta { color: #8b949e; margin-bottom: 1.5rem; }
    .risk-score { font-size: 1.4rem; font-weight: bold; }
    .finding { border: 1px solid #30363d; margin: .4rem 0; padding: .6rem .8rem; border-radius: 6px; }
    .critical { border-left: 4px solid #f85149; }
    .high     { border-left: 4px solid #ff7b72; }
    .medium   { border-left: 4px solid #ffa657; }
    .low      { border-left: 4px solid #3fb950; }
    .info     { border-left: 4px solid #58a6ff; }
    .badge { display: inline-block; padding: .1rem .4rem; border-radius: 3px; font-size: .75rem; font-weight: bold; margin-right: .4rem; }
    .badge-critical { background: #f85149; color: #0d1117; }
    .badge-high     { background: #ff7b72; color: #0d1117; }
    .badge-medium   { background: #ffa657; color: #0d1117; }
    .badge-low      { background: #3fb950; color: #0d1117; }
    .badge-info     { background: #58a6ff; color: #0d1117; }
    code { background: #161b22; padding: .15rem .3rem; border-radius: 3px; font-size: .85rem; color: #a5d6ff; }
    ul { padding-left: 1.5rem; }
    li { margin: .3rem 0; }
  </style>
</head>
<body>
  <h1>SecFlow Threat Report</h1>
  <div class="meta">
    <p>Target: <code>{{ report.input }}</code></p>
    <p>Total passes: <strong>{{ report.total_passes }}</strong></p>
    <p class="risk-score">Overall risk score: <span style="color: {% if report.overall_risk_score >= 7 %}#f85149{% elif report.overall_risk_score >= 4 %}#ffa657{% else %}#3fb950{% endif %}">{{ report.overall_risk_score }}/10</span></p>
  </div>

  <h2>Executive Summary</h2>
  <p>{{ report.summary }}</p>

  <h2>Findings Timeline</h2>
  {% for pass in report.passes %}
  <h3>Pass {{ pass.pass_number }} — {{ pass.analyzer | upper }}</h3>
  {% if pass.findings %}
    {% for f in pass.findings %}
    <div class="finding {{ f.severity }}">
      <span class="badge badge-{{ f.severity }}">{{ f.severity | upper }}</span>
      <strong>{{ f.type }}</strong> — {{ f.detail }}
      {% if f.evidence %}
      <br><code>{{ f.evidence[:200] }}</code>
      {% endif %}
    </div>
    {% endfor %}
  {% else %}
    <p style="color: #8b949e;">No findings recorded for this pass.</p>
  {% endif %}
  {% endfor %}

  <h2>Recommendations</h2>
  <ul>
    {% for rec in report.recommendations %}
    <li>{{ rec }}</li>
    {% endfor %}
  </ul>
</body>
</html>
"""


def _ask_gemini_to_format(findings_json: str) -> dict[str, Any]:
    """Send raw findings to Gemini and get a structured PWNDoc report."""
    prompt = f"""You are a professional cybersecurity report writer for a tool called SecFlow.

Below is raw JSON output from an automated multi-pass threat analysis pipeline.
Each item in the array is one analyzer pass with its findings.

Raw findings:
{findings_json}

Your task: produce a structured, professional threat report as a JSON object.
The JSON must conform EXACTLY to this schema:
{{
  "input": "the analyzed input (file path, URL, IP, or domain)",
  "total_passes": <number of passes>,
  "overall_risk_score": <max risk_score seen across all passes, 0.0-10.0>,
  "summary": "2-3 sentence executive summary describing what was found and the threat level",
  "passes": [
    {{
      "pass_number": 1,
      "analyzer": "malware|steg|recon|web|url",
      "findings": [
        {{
          "type": "finding_type",
          "detail": "human-readable description",
          "severity": "critical|high|medium|low|info",
          "evidence": "supporting evidence string"
        }}
      ]
    }}
  ],
  "recommendations": [
    "Actionable recommendation 1",
    "Actionable recommendation 2"
  ]
}}

Requirements:
- Use ALL findings from the input, do not omit any pass.
- Recommendations must be specific and actionable, not generic.
- overall_risk_score is the highest risk_score across all passes.
- summary must reflect actual findings.
- Respond ONLY with valid JSON. No markdown, no code fences, no extra text.
"""

    client = _get_client()
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            max_output_tokens=4096,
        ),
    )
    text = response.text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def _validate_report(report_data: dict[str, Any]) -> None:
    """Validate report data against the PWNDoc JSON schema."""
    schema = json.loads(SCHEMA_PATH.read_text())
    validate(instance=report_data, schema=schema)


def _render_html(report_data: dict[str, Any]) -> str:
    template = Template(HTML_TEMPLATE)

    class ReportObj:
        def __init__(self, d: dict) -> None:
            self.__dict__.update(d)
            self.passes = [type("Pass", (), p)() for p in d.get("passes", [])]
            for p in self.passes:
                p.findings = [type("Finding", (), f)() for f in getattr(p, "findings", [])]  # type: ignore[attr-defined]

    return template.render(report=ReportObj(report_data))


def _render_pdf(report_data: dict[str, Any], pdf_path: Path) -> None:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, "SecFlow Threat Report", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 7, f"Target: {report_data.get('input', '?')}", ln=True)
    pdf.cell(0, 7, f"Overall Risk Score: {report_data.get('overall_risk_score', 0)}/10", ln=True)
    pdf.cell(0, 7, f"Total Passes: {report_data.get('total_passes', 0)}", ln=True)
    pdf.ln(4)

    # Summary
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 9, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(0, 6, report_data.get("summary", ""))
    pdf.ln(4)

    # Passes
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 9, "Findings Timeline", ln=True)
    for pass_data in report_data.get("passes", []):
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, f"Pass {pass_data['pass_number']} — {pass_data['analyzer'].upper()}", ln=True)
        pdf.set_font("Helvetica", size=10)
        for finding in pass_data.get("findings", []):
            sev = finding.get("severity", "info").upper()
            detail = finding.get("detail", "")
            pdf.multi_cell(0, 5, f"  [{sev}] {detail}")
        pdf.ln(2)

    # Recommendations
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 9, "Recommendations", ln=True)
    pdf.set_font("Helvetica", size=11)
    for rec in report_data.get("recommendations", []):
        pdf.multi_cell(0, 6, f"\u2022 {rec}")

    pdf.output(str(pdf_path))


def generate_report(
    findings_json: str,
    output_dir: str = "/tmp/secflow_reports",
    base_name: str = "report",
) -> dict[str, str]:
    """
    Generate JSON, HTML, and PDF reports from findings JSON.

    Args:
        findings_json: serialized FindingsStore.to_json() output
        output_dir:    directory to write report files into
        base_name:     filename stem (default "report")

    Returns:
        dict of { "json": path, "html": path, "pdf": path }
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Format via Gemini
    try:
        report_data = _ask_gemini_to_format(findings_json)
    except Exception as e:
        log.error(f"Gemini report formatting failed: {e}")
        # Fallback: build a minimal report directly from raw findings
        findings = json.loads(findings_json)
        report_data = {
            "input": findings[0].get("input", "unknown") if findings else "unknown",
            "total_passes": len(findings),
            "overall_risk_score": max((f.get("risk_score", 0) for f in findings), default=0),
            "summary": "Automated analysis completed. Gemini formatting unavailable.",
            "passes": [
                {
                    "pass_number": f.get("pass", i + 1),
                    "analyzer": f.get("analyzer", "unknown"),
                    "findings": f.get("findings", []),
                }
                for i, f in enumerate(findings)
            ],
            "recommendations": ["Review the raw findings output for details."],
        }

    # Validate against schema
    try:
        _validate_report(report_data)
    except ValidationError as e:
        log.warning(f"Report schema validation warning: {e.message}")
        # Continue — don't block report generation over schema differences

    # Write JSON
    json_path = out / f"{base_name}.json"
    json_path.write_text(json.dumps(report_data, indent=2))

    # Write HTML
    html_path = out / f"{base_name}.html"
    html_path.write_text(_render_html(report_data))

    # Write PDF
    pdf_path = out / f"{base_name}.pdf"
    try:
        _render_pdf(report_data, pdf_path)
    except Exception as e:
        log.error(f"PDF generation failed: {e}")
        pdf_path.touch()  # create empty file so callers don't crash

    log.info(f"Report written to {output_dir}: json, html, pdf")
    return {
        "json": str(json_path),
        "html": str(html_path),
        "pdf":  str(pdf_path),
    }
