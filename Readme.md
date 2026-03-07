# SecFlow

> **Fully Automated Threat Analysis Pipeline with PWNDoc Reporting**

SecFlow is a multi-vector security analysis platform that accepts any input — file, URL, IP, domain, or image — routes it through specialized analyzers via an AI-driven orchestration loop, and produces a professional PWNDoc report (HTML, exportable to PDF) summarizing all findings, risk scores, and actionable recommendations.

Built for security analysts and SOC teams who need a single platform instead of manually correlating results across multiple tools.

---

## Features

- **Auto-Pipeline** — Drop in any input and let SecFlow handle routing, analysis, and reporting automatically
- **Five Specialized Analyzers** — Malware, Steganography, Reconnaissance, Web Vulnerability, and Macro/Office
- **AI-Driven Routing** — Groq `qwen/qwen3-32b` decides which analyzer runs next based on each pass's findings
- **Smart First-Pass Classification** — Deterministic rules (`file` + `python-magic`) route on pass 1; AI only invoked when type is ambiguous
- **Download-and-Analyze** — When AI has no next tool but passes remain, automatically downloads HTTP payloads found in analyzer output and routes them through appropriate analyzers
- **Configurable Loop Depth** — Run the analysis loop for 3, 4, or 5 passes; exits early if AI signals no further signals
- **Persistent Findings Store** — All output across every loop iteration is accumulated for the final report
- **PWNDoc HTML Report** — AI-formatted, browser-printable report with one-click "Export PDF" button
- **VirusTotal Integration** — Both Malware and Macro analyzers query VirusTotal API v3 for threat intelligence
- **Standalone Analyzer Mode** — Use any single analyzer independently via its own HTTP API

---

## How It Works

```
User Input (file / URL / IP / domain / image)
        │
        ▼
┌─────────────────────────────┐
│   Input Classifier          │  file + python-magic → deterministic rule
│   (Rule-based, no AI)       │  → if unknown type: Groq AI fallback
└──────────────┬──────────────┘
               │  first analyzer
               ▼
┌─────────────────────────────────────────────────────┐
│   Analyzer Loop (N passes, N = 3 / 4 / 5)          │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │  Run Analyzer (HTTP → Docker microservice)  │   │
│  │  Malware / Steg / Recon / Web / Macro       │   │
│  └────────┬────────────────────────────────────┘   │
│           │ findings + raw_output                   │
│  ┌────────▼────────────────────────────────────┐   │
│  │  AI Routing Engine  (Groq qwen/qwen3-32b)   │   │
│  │  Extracts IOCs → asks AI → next_tool+target │   │
│  └────────┬────────────────────────────────────┘   │
│           │                                         │
│     ┌─────┴────────────────┐                        │
│   tool                   null (no next tool)        │
│     │                       │                        │
│     │               Try downloading HTTP payloads   │
│     │               from raw_output URLs →          │
│     │               run appropriate analyzer        │
│     └─────────────── repeat ───────────────────────┘
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────┐
│   Findings Store            │  All passes, all findings accumulated
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│   Report Generator          │  Groq summary → PWNDoc HTML
│                             │  (one-click Export PDF in browser)
└─────────────────────────────┘
```

---

## Analyzers

| Analyzer | Port | Input Types | Tools / APIs |
|---|---|---|---|
| Malware | 5001 | EXE, DLL, ELF, binary | Ghidra decompilation, objdump, VirusTotal API v3 |
| Steganography | 5002 | PNG, JPG, BMP, GIF, TIFF | LSB analysis, binwalk, zsteg, steghide, ExifTool |
| Reconnaissance | 5003 | IPs, domains, emails, phones, usernames | ip-api, Talos, Tor check, ThreatFox, Tranco, XposedOrNot |
| Web Vulnerability | 5005 | URLs | Security header audit, fingerprinting, vuln scanning |
| Macro / Office | 5006 | DOC, DOCX, XLS, XLSX, XLSM, PPT, RTF | oletools (olevba), VirusTotal API v3 |

---

## Example Runs

**Malicious Office document:**
```
Input: invoice.xlsm

Pass 1 — Rule: .xlsm → Macro Analyzer
         → olevba: AutoExec + Suspicious macros, IOC: http://evil.sh/drop.exe
         → VT: 12/70 engines flagged

Pass 2 — AI: URL found in IOCs → Web Analyzer
         → http://evil.sh/drop.exe — endpoint alive, 302 redirect to CDN

Pass 3 — AI: no further signals, but URL in raw_output
         → Download payload: drop.exe → Malware Analyzer
         → Ghidra decompile, 45/70 VT detections, Trojan.GenericKDZ

Loop ends → PWNDoc HTML report generated ("Export PDF" in browser)
```

**Suspicious image:**
```
Input: profile.png

Pass 1 — Rule: image/png → Steg Analyzer
         → binwalk: embedded ELF binary at offset 0x8200

Pass 2 — AI: extracted binary → Malware Analyzer
         → C2 callout to 192.168.1.100 found in Ghidra decompile

Pass 3 — AI: IP found → Recon Analyzer
         → Talos: blacklisted, Tor exit node

Loop ends → Report generated
```

---

## Project Structure

```
secflow/
├── backend/
│   ├── orchestrator/       # Pipeline orchestrator (port 5000)
│   │   ├── app/
│   │   │   ├── routes.py           ← POST /api/smart-analyze
│   │   │   ├── orchestrator.py     ← Pipeline loop + download-and-analyze
│   │   │   ├── classifier/
│   │   │   │   ├── classifier.py   ← python-magic + file command
│   │   │   │   └── rules.py        ← Deterministic routing rules
│   │   │   ├── ai/
│   │   │   │   ├── engine.py       ← Groq qwen/qwen3-32b wrapper
│   │   │   │   └── keywords.txt    ← Fallback grep keyword list
│   │   │   ├── adapters/           ← Translates analyzer responses
│   │   │   │   ├── malware_adapter.py
│   │   │   │   ├── steg_adapter.py
│   │   │   │   ├── recon_adapter.py
│   │   │   │   ├── web_adapter.py
│   │   │   │   └── macro_adapter.py
│   │   │   ├── store/
│   │   │   │   └── findings_store.py
│   │   │   └── reporter/
│   │   │       └── report_generator.py  ← PWNDoc HTML + Export PDF
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── Malware-Analyzer/   # Ghidra + objdump + VirusTotal (port 5001)
│   ├── Steg-Analyzer/      # steghide + binwalk + zsteg (port 5002)
│   ├── Recon-Analyzer/     # ip-api + ThreatFox + OSINT (port 5003)
│   ├── Web-Analyzer/       # HTTP vuln scanner (port 5005)
│   ├── macro-analyzer/     # oletools + VirusTotal (port 5006)
│   └── compose.yml         # All 6 services on secflow-net
├── frontend/           # UI (planned — later phase)
├── docs/               # Architecture, pipeline flow, analyzer docs
├── AGENTS.md           # Agent architecture and coding instructions
└── Readme.md           # This file
```

---

## Documentation

> Backend documentation is the source of truth for service APIs and developer workflows.

| Document | Description |
|---|---|
| [ProjectDetails.md](ProjectDetails.md) | Full project specification and design |
| [AGENTS.md](AGENTS.md) | Agent architecture and AI coding instructions |
| [docs/architecture.md](docs/architecture.md) | System component and data-flow architecture |
| [docs/pipeline-flow.md](docs/pipeline-flow.md) | Detailed pipeline loop logic |
| [docs/analyzers.md](docs/analyzers.md) | Per-analyzer capability and interface spec |
| [docs/migration.md](docs/migration.md) | Integration guide for the analyzer microservices |
| [backend/Readme.md](backend/Readme.md) | Backend setup and development guide |
| [backend/Recon-Analyzer/README.md](backend/Recon-Analyzer/README.md) | Recon Analyzer service documentation |
| [backend/Malware-Analyzer/README.md](backend/Malware-Analyzer/README.md) | Malware Analyzer service documentation |
| [backend/Web-Analyzer/README.md](backend/Web-Analyzer/README.md) | Web Analyzer service overview |
| [backend/Web-Analyzer/QUICKSTART.md](backend/Web-Analyzer/QUICKSTART.md) | Web Analyzer quick start |
| [backend/Web-Analyzer/API_DOCUMENTATION.md](backend/Web-Analyzer/API_DOCUMENTATION.md) | Web Analyzer API reference |
| [backend/Web-Analyzer/DEVELOPMENT.md](backend/Web-Analyzer/DEVELOPMENT.md) | Web Analyzer development notes |
| [frontend/Readme.md](frontend/Readme.md) | Frontend setup and development guide |

---

## AI Model — Why Groq instead of Gemini

SecFlow originally used Google Gemini for the AI Decision Engine. It was migrated to **Groq + `qwen/qwen3-32b`** for the following reasons:

- **Speed** — Groq's LPU hardware delivers significantly faster inference than Gemini API round-trips, which matters when the AI is called on every pipeline pass.
- **OpenAI-compatible API** — Groq exposes an OpenAI-compatible REST API, meaning the standard `openai` Python SDK works directly with `base_url="https://api.groq.com/openai/v1"`. No vendor-specific SDK required.
- **Structured JSON reliability** — `qwen/qwen3-32b` reliably returns well-formed JSON even without function-calling schemas, which is how SecFlow uses it (prompt-level instruction to return `{"next_tool", "target", "reasoning"}`).
- **`/no_think` mode** — Qwen3 supports a system message of `"/no_think"` that disables chain-of-thought reasoning, giving direct answers faster — ideal for routing decisions.
- **Rate limits** — Groq's free tier is generous enough for development without running into quota errors.

The report summary (executive summary section) is also generated by Groq `qwen/qwen3-32b`.

---

## Status

> Backend pipeline is fully operational. Frontend UI is planned for a later phase.

| Component | Status |
|---|---|
| Orchestrator + Classifier + AI Engine | ✅ Complete |
| Malware Analyzer (Ghidra + VirusTotal) | ✅ Complete |
| Steg Analyzer (binwalk + zsteg + steghide) | ✅ Complete |
| Recon Analyzer (ip-api + ThreatFox + OSINT) | ✅ Complete |
| Web Vulnerability Analyzer | ✅ Complete |
| Macro Analyzer (oletools + VirusTotal) | ✅ Complete |
| Download-and-Analyze payload fallback | ✅ Complete |
| PWNDoc HTML Report + Export PDF button | ✅ Complete |
| Frontend UI | ⏳ Planned |
