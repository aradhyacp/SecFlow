import type { PwndocReport } from "./schema.js";
import type { RuleArtifact } from "../graph/schema/rules.js";
import type { SecFlowFinding } from "../graph/schema/analyzer.js";
import { riskLabel } from "./build.js";

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function prettyEvidence(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      // Keep the original evidence when it is not valid JSON.
    }
  }
  return value;
}

function renderEvidence(finding: SecFlowFinding): string {
  if (!finding.evidence) {
    return "";
  }
  const evidence = prettyEvidence(finding.evidence);
  return `<details class="evidence"><summary>Evidence <span class="muted">(${evidence.length.toLocaleString()} chars)</span></summary><pre>${escapeHtml(evidence)}</pre></details>`;
}

function renderFinding(finding: SecFlowFinding): string {
  const extracted = finding.extracted_path
    ? `<div class="meta">Extracted file: <code>${escapeHtml(finding.extracted_path)}</code></div>`
    : "";
  return `<article class="finding finding-${escapeHtml(finding.severity)}">
  <div class="finding-head"><span class="sev sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span><strong>${escapeHtml(finding.type)}</strong></div>
  <p>${escapeHtml(finding.detail)}</p>
  ${extracted}
  ${renderEvidence(finding)}
</article>`;
}

function renderPasses(report: PwndocReport): string {
  return report.passes
    .map(
      (pass) => `<section class="pass">
  <h3>Pass ${pass.pass_number} — ${escapeHtml(pass.analyzer)}</h3>
  <div class="finding-list">${pass.findings.map(renderFinding).join("") || '<p class="muted">No findings in this pass.</p>'}</div>
</section>`,
    )
    .join("");
}

function renderRulesSection(
  label: string,
  section:
    | {
        reasoning?: string;
        total_rules: number;
        rules: Array<{
          rule_name: string;
          description?: string;
          reasoning?: string;
          tags?: string[];
          rule_text: string;
        }>;
      }
    | undefined,
): string {
  if (!section) {
    return "";
  }
  const cards = section.rules
    .map(
      (rule, index) => `<article class="rule-card">
  <h4>${index + 1}. ${escapeHtml(rule.rule_name)}</h4>
  ${rule.description ? `<p>${escapeHtml(rule.description)}</p>` : ""}
  ${rule.tags && rule.tags.length > 0 ? `<div class="tags">${rule.tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}</div>` : ""}
  ${rule.reasoning ? `<div class="meta"><strong>Why this rule:</strong> ${escapeHtml(rule.reasoning)}</div>` : ""}
  <details class="evidence"><summary>View ${escapeHtml(label)} rule text</summary><pre>${escapeHtml(rule.rule_text)}</pre></details>
</article>`,
    )
    .join("");
  return `<section class="rules">
  <h2>${escapeHtml(label)} rules <span class="muted">(${section.total_rules})</span></h2>
  ${section.reasoning ? `<p class="muted">${escapeHtml(section.reasoning)}</p>` : ""}
  ${cards || '<p class="muted">No deployable rules were generated.</p>'}
</section>`;
}

function renderInvalidRules(report: PwndocReport): string {
  const invalid = [...(report.rules?.yara ?? []), ...(report.rules?.sigma ?? [])].filter(
    (rule) => rule.status === "invalid",
  );
  if (invalid.length === 0) {
    return "";
  }
  return `<section class="rules">
  <h2>Rules that failed validation <span class="muted">(${invalid.length})</span></h2>
  ${invalid
    .map(
      (rule: RuleArtifact) => `<article class="rule-card invalid">
  <h4>${escapeHtml(rule.name ?? `${rule.kind.toUpperCase()} rule`)}</h4>
  <div class="meta">Status: ${escapeHtml(rule.status)}</div>
  <ul>${rule.validationErrors.map((error) => `<li>${escapeHtml(error)}</li>`).join("")}</ul>
  <details class="evidence"><summary>View rejected rule text</summary><pre>${escapeHtml(rule.content)}</pre></details>
</article>`,
    )
    .join("")}
</section>`;
}

function renderTools(report: PwndocReport): string {
  if (!report.tools || report.tools.length === 0) {
    return "";
  }
  return `<section class="tools">
  <h2>Executed tools</h2>
  <table>
    <thead><tr><th>Pass</th><th>Tool</th><th>Status</th><th>Duration</th><th>Findings</th><th>Risk</th></tr></thead>
    <tbody>${report.tools
      .map(
        (tool) => `<tr>
      <td>${tool.pass}</td>
      <td><code>${escapeHtml(tool.tool)}</code></td>
      <td>${escapeHtml(tool.status)}</td>
      <td>${tool.durationMs.toLocaleString()} ms</td>
      <td>${tool.findingCount}</td>
      <td>${tool.riskScore.toFixed(1)}</td>
    </tr>`,
      )
      .join("")}</tbody>
  </table>
</section>`;
}

function renderErrors(report: PwndocReport): string {
  if (!report.errors || report.errors.length === 0) {
    return "";
  }
  return `<section class="errors">
  <h2>Errors and limitations</h2>
  <ul>${report.errors
    .map(
      (error) =>
        `<li><strong>${escapeHtml(error.stage)}/${escapeHtml(error.code)}:</strong> ${escapeHtml(error.message)}${error.recoverable ? ' <span class="muted">(recoverable)</span>' : ""}</li>`,
    )
    .join("")}</ul>
</section>`;
}

function renderLimitations(report: PwndocReport): string {
  if (!report.limitations || report.limitations.length === 0) {
    return "";
  }
  return `<section class="limitations">
  <h2>Limitations</h2>
  <ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
</section>`;
}

const STYLES = `
:root { color-scheme: light; --ink:#172033; --muted:#65708a; --line:#dfe5f0; --accent:#1d4ed8; --bg:#f5f7fb; --card:#fff; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
main { max-width:1120px; margin:0 auto; padding:32px 24px 64px; }
header.hero { background:linear-gradient(135deg,#111827,#1d4ed8); color:#fff; border-radius:18px; padding:28px 32px; margin-bottom:24px; }
header.hero h1 { margin:0 0 8px; font-size:1.8rem; }
header.hero p { margin:4px 0; color:#dbeafe; }
.risk { display:inline-block; margin-top:14px; padding:8px 14px; border-radius:999px; background:rgba(255,255,255,.16); font-weight:700; }
.risk-critical { background:#b91c1c; }
.risk-high { background:#c2410c; }
.risk-medium { background:#b45309; }
.risk-low { background:#047857; }
.risk-informational { background:#1d4ed8; }
section { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:22px 24px; margin:18px 0; }
h2 { margin:0 0 14px; font-size:1.2rem; }
h3 { margin:0 0 12px; font-size:1.05rem; }
h4 { margin:0 0 8px; }
p { margin:8px 0; }
.muted { color:var(--muted); font-weight:400; }
.meta { color:var(--muted); font-size:.9rem; margin:6px 0; }
.finding { border-left:4px solid var(--line); padding:10px 14px; margin:12px 0; background:#fbfcff; border-radius:0 8px 8px 0; }
.finding-critical { border-left-color:#b91c1c; }
.finding-high { border-left-color:#dc2626; }
.finding-medium { border-left-color:#d97706; }
.finding-low { border-left-color:#0891b2; }
.finding-info { border-left-color:#64748b; }
.finding-head { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.sev { font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; padding:2px 7px; border-radius:999px; background:#e2e8f0; }
.sev-critical,.sev-high { background:#fee2e2; color:#991b1b; }
.sev-medium { background:#fef3c7; color:#92400e; }
.sev-low { background:#cffafe; color:#155e75; }
.sev-info { background:#e2e8f0; color:#334155; }
details.evidence { margin-top:10px; }
details.evidence summary { cursor:pointer; color:var(--accent); font-weight:600; }
pre { background:#0f172a; color:#e2e8f0; padding:14px; border-radius:8px; overflow:auto; max-height:520px; font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap; word-break:break-word; }
table { width:100%; border-collapse:collapse; font-size:.9rem; }
th,td { text-align:left; border-bottom:1px solid var(--line); padding:8px 10px; vertical-align:top; }
th { color:var(--muted); font-weight:600; }
.tags { display:flex; gap:6px; flex-wrap:wrap; margin:8px 0; }
.tags span { background:#eef2ff; color:#3730a3; padding:2px 8px; border-radius:999px; font-size:.78rem; }
.rule-card { border:1px solid var(--line); border-radius:10px; padding:14px; margin:12px 0; }
.rule-card.invalid { border-color:#fecaca; background:#fff7f7; }
ul { margin:8px 0; padding-left:22px; }
li { margin:5px 0; }
code { font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; background:#eef2f7; padding:1px 5px; border-radius:4px; }
footer { text-align:center; color:var(--muted); font-size:.82rem; margin-top:28px; }
@media (max-width:700px) { main { padding:16px 12px; } header.hero { padding:22px; } section { padding:16px; } }
`;

export function renderReportHtml(report: PwndocReport, jobId: string): string {
  const score = report.overall_risk_score;
  const label = riskLabel(score);
  const generated = report.timestamps?.generated_at ?? new Date(0).toISOString();
  const threat = report.threat_intel;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecFlow report — ${escapeHtml(report.input)}</title>
<style>${STYLES}</style>
</head>
<body>
<main>
<header class="hero">
  <h1>SecFlow Threat Analysis</h1>
  <p>Input: <strong>${escapeHtml(report.input)}</strong></p>
  <p>Analyzers: ${escapeHtml((report.analyzers_executed ?? []).join(", ") || "none")} · Passes: ${report.total_passes}</p>
  <div class="risk risk-${label}">Overall risk ${score.toFixed(1)}/10 · ${label}</div>
</header>

<section>
  <h2>Executive summary</h2>
  <p>${escapeHtml(report.summary)}</p>
</section>

<section>
  <h2>Recommendations</h2>
  <ul>${report.recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("") || "<li>No recommendations.</li>"}</ul>
</section>

<section>
  <h2>Analysis timeline</h2>
  ${renderPasses(report)}
</section>

${renderRulesSection("YARA", threat?.yara)}
${renderRulesSection("SIGMA", threat?.sigma)}
${renderInvalidRules(report)}
${renderTools(report)}
${renderErrors(report)}
${renderLimitations(report)}

<footer>SecFlow automated threat analysis · Report ID ${escapeHtml(jobId)} · Generated ${escapeHtml(generated)}</footer>
</main>
</body>
</html>
`;
}
