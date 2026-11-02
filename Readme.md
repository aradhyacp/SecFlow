<div align="center">

<img src="https://img.shields.io/badge/SecFlow-Threat%20Analysis%20Pipeline-critical?style=for-the-badge&logo=shield&logoColor=white" alt="SecFlow">

# SecFlow

### Fully Automated Multi-Vector Threat Analysis Pipeline

[![TypeScript](https://img.shields.io/badge/Orchestrator-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![LangGraph](https://img.shields.io/badge/LangGraph.js-1.x-1C3C3C?style=flat-square&logo=langchain&logoColor=white)](https://langchain-ai.github.io/langgraphjs/)
[![OpenRouter](https://img.shields.io/badge/AI-OpenRouter-6467F2?style=flat-square&logo=openai&logoColor=white)](https://openrouter.ai)
[![Python analyzers](https://img.shields.io/badge/Analyzers-Python%203.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-394EFF?style=flat-square&logo=virustotal&logoColor=white)](https://virustotal.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](https://github.com/aradhyacp/SecFlow/pulls)

**Drop in any file, URL, IP, domain, or image. SecFlow routes it through specialized analyzers, reasons about findings with AI, and produces a professional security report with YARA rules, SIGMA rules, and exportable PDF — automatically.**

<img src="https://github.com/aradhyacp/SecFlow/blob/main/SecFlowSocialCard.jpg" alt="SecFlow Social Card">


[Quick Start](#-quick-start) · [Architecture](#architecture) · [Report Output](#report-output) · [Docs](#-documentation)

</div>

---

## What is SecFlow?

SecFlow is an **open-source automated threat analysis pipeline** built for security analysts, SOC teams, and researchers. Instead of manually running disparate tools and correlating results, SecFlow:

1. **Classifies** your input using deterministic rules (no AI on pass 1)
2. **Routes** it through the right specialized analyzer via HTTP microservices
3. **Reasons** about each pass's findings with an OpenRouter model to decide the next step
4. **Repeats** — following IOCs, downloading payloads, pivoting across analyzers
5. **Reports** — generates a PWNDoc HTML report with YARA detection rules, SIGMA SIEM rules, MITRE ATT&CK mappings, and one-click PDF export

---

## Features

| Feature | Detail |
|---|---|
| **AI-Driven Routing** | OpenRouter `nvidia/nemotron-3-ultra-550b-a55b:free` decides the next analyzer after each pass — model is configurable |
| **5 Specialized Analyzers** | Malware · Steganography · Reconnaissance · Web Vulnerability · Macro/Office |
| **Smart First-Pass** | Deterministic file/target rules on pass 1 — AI is only called when the type is ambiguous |
| **Download-and-Analyze** | Follows IOCs — downloads payloads found in raw output and routes them through the right analyzer |
| **YARA Rule Generation** | Auto-generates 2–5 deployable YARA rules per analysis, each citing the exact evidence that drove it |
| **SIGMA Rule Generation** | Auto-generates 2–4 SIGMA rules for Splunk / Elastic / Sentinel — covering different log sources |
| **MITRE ATT&CK Mapping** | Every finding mapped to real TTP IDs with tactic names |
| **Dual Report Formats** | HTML report (print-to-PDF in browser) + structured JSON report (feed directly to AI for further analysis) |
| **React Dashboard** | Full frontend UI — submit analyses, view live pipeline progress, browse results per analyzer |
| **VirusTotal Integration** | Both Malware and Macro analyzers query 70+ AV engines via VT API v3 |
| **Configurable Loop Depth** | 3, 4, or 5 passes — exits early if AI signals no further signals |
| **Standalone Mode** | Every analyzer microservice exposes its own REST API — use them independently |

---

## Architecture

```
User Input (file / URL / IP / domain / image)
        │
        ▼
┌────────────────────────────────┐
│   Input Classifier             │  deterministic type rules
│   (Rule-based, pass 1 only)    │  unknown type? → OpenRouter fallback
└───────────────┬────────────────┘
                │  first analyzer selected
                ▼
┌────────────────────────────────────────────────────────┐
│              Analyzer Loop  (N = 3 / 4 / 5 passes)    │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Run Analyzer  (HTTP → Docker microservice)      │  │
│  │  Malware · Steg · Recon · Web · Macro                 │  │
│  └───────────────┬──────────────────────────────────┘  │
│                  │ findings + raw_output                │
│  ┌───────────────▼──────────────────────────────────┐  │
│  │  AI Routing Engine (LangGraph + OpenRouter)      │  │
│  │  IOC extraction → next_tool + target             │  │
│  └───────────────┬──────────────────────────────────┘  │
│                  │                                      │
│          ┌───────┴──────────────────┐                  │
│       next tool                  null                   │
│          │                          │                   │
│          │               Download HTTP payloads         │
│          │               from raw_output → re-analyze  │
│          └──────────────── repeat ────────────────────┘│
└─────────────────┬──────────────────────────────────────┘
                  │
                  ▼
┌────────────────────────────────┐
│  Findings Store                │  All passes · all findings accumulated
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────────────────┐
│  Threat Intelligence Engine                │
│  (OpenRouter · configurable model)        │
│  ├─ Threat Summary + MITRE ATT&CK TTPs    │
│  ├─ YARA Detection Rules (2–5 rules)      │
│  └─ SIGMA SIEM Rules (2–4 rules)          │
└───────────────┬────────────────────────────┘
                │
                ▼
┌────────────────────────────────┐
│  PWNDoc HTML Report            │  AI summary → browser-rendered HTML
│                                │  One-click Export PDF button
└────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- An OpenRouter API key (the default model has a free tier)
- A VirusTotal API key for malware/macro threat intelligence (optional but recommended)

### 1. Clone the repository

```bash
git clone https://github.com/aradhyacp/SecFlow.git
cd SecFlow/backend
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your keys:

```env
# Core keys
OPENROUTER_API_KEY=your_openrouter_api_key_here     # Required
VIRUSTOTAL_API_KEY=your_vt_api_key_here             # Recommended

# Optional — unlock additional OSINT capabilities
NUMVERIFY_API_KEY=your_numverify_key      # Phone number lookups
THREATFOX_API_KEY=your_threatfox_key      # Higher ThreatFox rate limits
ipAPI_KEY=your_ipapi_key                  # Higher ip-api.com rate limits

# Orchestrator model + limits
OPENROUTER_MODEL=nvidia/nemotron-3-ultra-550b-a55b:free
MODEL_MAX_CYCLES=12
TOTAL_ANALYSIS_TIMEOUT_MS=600000
ALLOW_PRIVATE_TARGETS=false                # true only for local demos
```

### 3. Start all services

```bash
docker compose up -d
```

This starts the six core services (plus Steg's PostgreSQL, Redis, and worker containers):

| Service | Port | Role |
|---|---|---|
| `orchestrator` | `5000` | Pipeline controller — main entry point |
| `malware-analyzer` | `5001` | Ghidra decompilation + VirusTotal |
| `steg-analyzer` | `5002` | binwalk + zsteg + steghide + ExifTool |
| `recon-analyzer` | `5003` | ip-api + ThreatFox + OSINT |
| `web-analyzer` | `5005` | HTTP vuln scanner + header audit |
| `macro-analyzer` | `5006` | oletools (olevba) + VirusTotal |

> **Note:** First start may take several minutes — the Malware Analyzer downloads Ghidra 12.0.1 (~500 MB) and requires a JDK 21 JVM.

### 4. Run your first analysis

**Analyze a file:**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -F "file=@/path/to/suspicious.exe" \
  -F "passes=3"
```

**Analyze a URL, IP, or domain:**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.100", "passes": 3}'
```

**Response:**
```json
{
  "job_id": "a1b2c3d4",
  "findings": [...],
  "report_paths": {
    "json": "/api/report/a1b2c3d4/json",
    "html": "/api/report/a1b2c3d4/html"
  }
}
```

Open `http://localhost:5000/api/report/<job_id>/html` in your browser to view the full report and export to PDF.

### 5. Launch the frontend

```bash
cd ../frontend
npm install
npm run dev
```

Open `http://localhost:5173` — the React dashboard lets you submit analyses, watch pipeline progress in real time, and browse results per analyzer.

---

## Analyzers

### Malware Analyzer — Port 5001

Analyzes executables and binaries with a three-layer approach:

- **Ghidra 12.0.1** (via `pyghidra`) — full decompilation of all functions to C pseudo-code
- **`objdump -d`** — assembly-level disassembly
- **VirusTotal API v3** — 70+ AV engine detections, behavioral tags, file reputation

**Supported:** `exe`, `dll`, `so`, `elf`, `bin`, `o`, `out` · Max 50 MB · Requires 4 GB RAM (Ghidra JVM)

---

### Steganography Analyzer — Port 5002

Detects hidden data embedded in images using multiple methods:

- **binwalk** — detects and extracts embedded files at binary offsets
- **foremost** — file carving from raw binary streams
- **zsteg** — LSB steganography detection in PNG/BMP
- **steghide** — passphrase-based steg detection in JPEG/BMP
- **ExifTool** — metadata extraction and anomaly detection

**Extracts embedded archives and queues them for re-analysis** in the next pipeline pass.

**Supported:** PNG, JPG, BMP, GIF, TIFF, WebP

---

### Reconnaissance Analyzer — Port 5003

Performs threat intelligence and OSINT on network identifiers:

**Scan mode** (IP / domain):

| Module | Source | What it checks |
|---|---|---|
| `ipapi` | ip-api.com | Country, ISP, ASN, geolocation |
| `talos` | Cisco Talos blocklist | IP reputation / blacklist |
| `tor` | Tor Project exit list | Tor exit node detection |
| `tranco` | Tranco ranking list | Domain popularity rank |
| `threatfox` | abuse.ch ThreatFox | Active IOC / malware association |

**Footprint mode** (email / phone / username):
- **Email** — XposedOrNot breach database (breach count, severity, password risk)
- **Phone** — NumVerify carrier + country + line type validation
- **Username** — Sagemode multithreaded profile discovery across social platforms

---

### Web Vulnerability Analyzer — Port 5005

Audits URLs and web endpoints:

- Security header analysis (CSP, HSTS, X-Frame-Options, etc.)
- Technology fingerprinting (server, frameworks, CMS)
- HTTP response analysis and redirect chain following
- Basic vulnerability scanning for common misconfigurations

---

### Macro / Office Analyzer — Port 5006

Dissects Office documents for malicious macros:

- **oletools (olevba)** — extracts and decompiles VBA/XLM macros
- **AutoExec detection** — flags macros that auto-run on open/close
- **IOC extraction** — URLs, IPs, file paths embedded in macro code
- **Obfuscation detection** — Base64, Chr() chains, hex encoding
- **VirusTotal API v3** — file reputation cross-check

**Supported:** `doc`, `docx`, `docm`, `xls`, `xlsx`, `xlsm`, `xlsb`, `ppt`, `pptx`, `pptm`, `rtf`

---

## Report Output

Every pipeline run produces **two report formats** saved to `backend/reports/<job_id>/`:

### HTML Report (`report.html`)

Open in any browser. Click **Export PDF** to print — no server-side PDF rendering needed, no dependencies.

Contains: executive summary · YARA rules · SIGMA rules · MITRE TTPs · per-pass evidence panels · VirusTotal engine badges.

### JSON Report (`report.json`)

Fully structured machine-readable output. Use this when you want to:
- Feed findings directly into another AI model for deeper analysis
- Ingest into a SIEM or ticketing system
- Diff two reports programmatically
- Build custom dashboards

The JSON mirrors the HTML exactly — every finding, YARA rule, SIGMA rule, IOC, and TTP is present in a clean, typed schema.

See [`examples/`](examples/) for sample input files and [`example_reports`](example_reports/) for real report outputs generated during development.

---

### Executive Summary
AI-written narrative (OpenRouter model) covering:
- Identified threat name and actor type classification
- Attack chain reconstruction (step-by-step)
- Confidence rating and overall risk score

### YARA Detection Rules
**2–5 production-ready YARA rules** generated by the configured OpenRouter model and compiled with YARA-X, each:
- Named with `SecFlow_[ThreatCategory]_[IndicatorType]` convention
- Containing valid YARA 4.x syntax — ready to import into any YARA-compatible scanner
- Including a `reasoning` field citing the exact evidence from the analysis that informed the rule
- Covering distinct aspects: file signatures, embedded strings, C2 indicators, packer signatures, memory patterns

```yara
rule SecFlow_Trojan_C2StringIndicator {
  meta:
    description = "Detects C2 callback string found in Ghidra decompilation"
    author      = "SecFlow AI"
    severity    = "high"
  strings:
    $c2 = "evil.sh/drop.exe"
    $ua = "Mozilla/4.0 (compatible; MSIE 6.0)"
  condition:
    any of them
}
```

### SIGMA SIEM Rules
**2–4 SIGMA rules** for immediate SIEM deployment, each:
- Covering a **different log source** (process creation, network, DNS, file events, registry)
- Including valid SIGMA syntax compatible with `sigma-cli` 0.x and pySigma
- Mapping tags to real MITRE ATT&CK tactics and technique IDs
- Importable into Splunk, Elastic Security, Microsoft Sentinel, Chronicle, QRadar

```yaml
title: Detect Suspicious AutoExec Macro Execution
id: f2a3b1c4-...
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'EXCEL.EXE'
      - '/automation'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1137.001
```

### MITRE ATT&CK TTPs
Every identified behavior mapped to real technique IDs with tactic names and reasoning.

### Per-Pass Evidence
Collapsible panels for each analyzer pass showing:
- Ghidra decompilation output (dark code block, collapsible)
- objdump disassembly (collapsible)
- VirusTotal engine detections (color-coded severity badges)
- Raw analyzer findings JSON

### Export PDF
One-click browser print dialog pre-configured for PDF export — no server-side PDF generation needed.

---

## Example Pipeline Runs

Sample input files are in [`examples/`](examples/) — includes real malware samples (`RealMalware.exe`, `ColorBug.exe`, `EarlyEnd.exe`, `.out` ELF binaries) and a malicious Office document (`nuclear_motor_example.docm`). Corresponding report outputs are in [`backend/reports/`](backend/reports/).

### Malicious Office Document

```
Input:  invoice.xlsm
Passes: 3

Pass 1 ─ Rule: .xlsm extension → Macro Analyzer
          olevba: AutoExec macro found
          IOC: http://evil.sh/drop.exe
          VT: 12/70 engines flagged

Pass 2 ─ AI: URL found in IOCs → Web Analyzer
          http://evil.sh/drop.exe — alive, 302 redirect to CDN

Pass 3 ─ AI: no further tool, but HTTP URL in raw_output
          Download: drop.exe → Malware Analyzer
          Ghidra: C2 callback string, packed PE
          VT: 45/70 detections — Trojan.GenericKDZ

Report  ─ PWNDoc HTML generated
          YARA: 4 rules (string, byte sig, packer, C2 domain)
          SIGMA: 3 rules (process_creation, network, registry)
          MITRE: T1566.001, T1059.005, T1071.001
```

### Suspicious Image with Embedded Payload

```
Input:  profile.png
Passes: 3

Pass 1 ─ Rule: image/png → Steg Analyzer
          binwalk: embedded ELF binary at offset 0x8200
          Archive extracted → queued for re-analysis

Pass 2 ─ Queue: extracted ELF → Malware Analyzer
          Ghidra: C2 callout to 192.168.1.100
          objdump: packed UPX section

Pass 3 ─ AI: IP found → Recon Analyzer
          Talos: blacklisted
          Tor: confirmed exit node
          ThreatFox: associated with AsyncRAT

Report  ─ Full chain documented
          YARA: 3 rules (ELF magic, UPX sig, C2 string)
          SIGMA: 2 rules (network_connection, dns_query)
```

### Suspicious Domain

```
Input:  malicious-domain.ru
Passes: 3

Pass 1 ─ Rule: domain regex → Recon Analyzer
          ipapi: RU, ISP: HostMaster LLC
          Talos: on blocklist
          ThreatFox: linked to Raccoon Stealer, confidence 95

Pass 2 ─ AI: ThreatFox hit → Web Analyzer
          /login endpoint returns 200, harvesting form detected

Pass 3 ─ AI: no futher signals — loop exits early

Report  ─ Executive summary + TTPs + SIGMA network rules
```

---

## Project Structure

```
SecFlow/
├── backend/
│   ├── compose.yml                 # All services on secflow-net
│   ├── .env.example                # All required + optional API keys
│   │
│   ├── orchestrator-ts/            # TypeScript + LangGraph.js controller (port 5000)
│   │   ├── src/
│   │   │   ├── index.ts            # Express bootstrap + graceful shutdown
│   │   │   ├── routes/             # /api/smart-analyze, /api/health, /api/report
│   │   │   ├── classifier/         # Deterministic input classification + rules
│   │   │   ├── graph/              # LangGraph state machine, decisions, loop
│   │   │   ├── analyzers/          # HTTP clients, adapters, validated tools
│   │   │   ├── pipeline/           # Runner, uploads, payload downloader
│   │   │   ├── security/           # SSRF/network guard
│   │   │   ├── rules/              # YARA-X + SIGMA generation/validation
│   │   │   ├── report/             # PWNDoc report builder + narrative
│   │   │   ├── prompts/            # Centralized, evidence-isolated prompts
│   │   │   └── model/              # OpenRouter provider + LangGraph adapter
│   │   ├── tests/                  # Unit, contract, parity and live-gated tests
│   │   ├── Dockerfile
│   │   └── package.json
│   │
│   ├── Malware-Analyzer/           # Ghidra + objdump + VirusTotal (port 5001)
│   ├── Steg-Analyzer/              # binwalk + zsteg + steghide (port 5002)
│   ├── Recon-Analyzer/             # ip-api + ThreatFox + OSINT (port 5003)
│   ├── Web-Analyzer/               # HTTP vuln scanner (port 5005)
│   └── macro-analyzer/             # oletools + VirusTotal (port 5006)
│
├── frontend/                       # React + Vite dashboard (port 5173)
│   └── src/
│       ├── pages/dashboard/        # Per-analyzer pages + smart pipeline UI
│       ├── components/             # Reusable UI components
│       └── pages/LandingPage.jsx   # Public landing page
│
├── examples/                       # Sample input files for testing
│   ├── RealMalware.exe             # Real malware sample
│   ├── ColorBug.exe / EarlyEnd.exe # PE test samples
│   ├── sample.out / sample2.out    # ELF binaries
│   └── nuclear_motor_example.docm  # Malicious Office document
│
├── docs/                           # Architecture + pipeline + analyzer docs
├── AGENTS.md                       # Agent architecture + coding conventions
└── Readme.md
```

---

## AI Models

SecFlow uses **OpenRouter** for all orchestrator inference. The default model is
`nvidia/nemotron-3-ultra-550b-a55b:free`; change `OPENROUTER_MODEL` to use a
different tool-capable model without code changes.

| Role | Model | Why |
|---|---|---|
| **Pipeline routing** | `OPENROUTER_MODEL` | Structured tool-calling decides the next analyzer after each pass |
| **Threat intelligence** | `OPENROUTER_MODEL` | YARA/SIGMA generation and MITRE ATT&CK mapping |
| **Report summary** | `OPENROUTER_MODEL` | Executive summary + recommendations |

The orchestrator calls OpenRouter through the Vercel AI SDK
(`@openrouter/ai-sdk-provider` + `ai`) and runs the decision loop as a single
LangGraph.js state graph. The analyzer microservices remain Python/Flask and are
still invoked over their existing HTTP APIs. Set
`OPENROUTER_API_KEY` in `backend/.env` before starting the stack.

**Why OpenRouter?** One gateway exposes many tool-capable models, including free
tiers, so SecFlow can switch models without changing the orchestration code.

---

## API Reference

All requests go to the orchestrator at `http://localhost:5000`.

### `POST /api/smart-analyze`

Submit a file or target for analysis.

**File input:**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -F "file=@sample.exe" \
  -F "passes=4"
```

**Target input (URL / IP / domain):**
```bash
curl -X POST http://localhost:5000/api/smart-analyze \
  -H "Content-Type: application/json" \
  -d '{"target": "https://suspicious-site.com", "passes": 5}'
```

### `GET /api/report/<job_id>/html`

Returns the full PWNDoc HTML report — open in browser, click **Export PDF** to save.

### `GET /api/report/<job_id>/json`

Returns the raw findings JSON for programmatic consumption.

### `GET /api/health`

Health check — returns `{"status": "healthy"}`.

---

## Environment Variables

| Variable | Service | Required | Description |
|---|---|---|---|
| `OPENROUTER_API_KEY` | orchestrator | ✅ | AI routing + rule generation + report narrative |
| `OPENROUTER_MODEL` | orchestrator | Optional | Model id (default `nvidia/nemotron-3-ultra-550b-a55b:free`) |
| `VIRUSTOTAL_API_KEY` | malware, macro | Recommended | VirusTotal API v3 file/URL analysis |
| `NUMVERIFY_API_KEY` | recon | Optional | Phone number validation (NumVerify) |
| `THREATFOX_API_KEY` | recon | Optional | Higher rate limit on ThreatFox IOC queries |
| `ipAPI_KEY` | recon | Optional | Higher rate limit on ip-api.com |
| `MODEL_MAX_CYCLES` | orchestrator | Optional | Maximum model decisions per run (default `12`) |
| `TOTAL_ANALYSIS_TIMEOUT_MS` | orchestrator | Optional | Whole-run deadline (default `600000`) |
| `ALLOW_PRIVATE_TARGETS` | orchestrator | Optional | Allow loopback/private targets (default `false`) |

---

## Status

| Component | Status |
|---|---|
| Orchestrator + Classifier + AI Engine | ✅ Complete |
| Malware Analyzer (Ghidra + VirusTotal) | ✅ Complete |
| Steg Analyzer (binwalk + zsteg + steghide) | ✅ Complete |
| Recon Analyzer (ip-api + ThreatFox + OSINT) | ✅ Complete |
| Web Vulnerability Analyzer | ✅ Complete |
| Macro Analyzer (oletools + VirusTotal) | ✅ Complete |
| Download-and-Analyze payload fallback | ✅ Complete |
| YARA Rule Auto-Generation | ✅ Complete |
| SIGMA Rule Auto-Generation | ✅ Complete |
| MITRE ATT&CK TTP Mapping | ✅ Complete |
| HTML Report + JSON Report + Export PDF | ✅ Complete |
| React Frontend Dashboard | ✅ Complete |

---

## Documentation

| Document | Description |
|---|---|
| [AGENTS.md](AGENTS.md) | Agent architecture, service contracts, and AI coding instructions |
| [ProjectDetails.md](ProjectDetails.md) | Full project specification and design decisions |
| [docs/architecture.md](docs/architecture.md) | System component and data-flow diagrams |
| [docs/pipeline-flow.md](docs/pipeline-flow.md) | Detailed pipeline loop logic and decision tree |
| [docs/analyzers.md](docs/analyzers.md) | Per-analyzer capability and interface spec |
| [docs/migration.md](docs/migration.md) | Integration guide for the analyzer microservices |
| [backend/Readme.md](backend/Readme.md) | Backend setup, development, and troubleshooting guide |

---

## Contributing

Contributions are welcome. SecFlow is open source and actively maintained.

1. Fork [aradhyacp/SecFlow](https://github.com/aradhyacp/SecFlow)
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make changes — see [AGENTS.md](AGENTS.md) for architecture conventions and service contracts
4. Open a pull request

**Good first issues:** New IOC extraction patterns, SIGMA rule improvements, additional OSINT modules, frontend analyzer pages, report export improvements.

If SecFlow is useful to your work or research, consider [sponsoring the project](https://github.com/sponsors/aradhyacp) — it helps keep the free-tier infrastructure and development going.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for security analysts who need answers, not more tools to juggle.**

If SecFlow helps you, give it a star — it helps others discover the project.

[github.com/aradhyacp/SecFlow](https://github.com/aradhyacp/SecFlow)

---

`#cybersecurity` `#threatintelligence` `#malwareanalysis` `#yara` `#sigma` `#soc` `#dfir` `#infosec` `#osint` `#reverseengineering` `#steganography` `#virustotal` `#ghidra` `#docker` `#typescript` `#langgraph` `#openrouter` `#openSource` `#automation` `#mitre` `#attackframework` `#secops` `#blueTeam` `#incidentResponse` `#siem` `#edr` `#ioc` `#pwndoc` `#llm` `#aiSecurity`

</div>
