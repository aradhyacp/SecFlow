# SecFlow

> **Fully Automated Threat Analysis Pipeline with PWNDoc Reporting**

SecFlow is a multi-vector security analysis platform that accepts any input — file, URL, IP, domain, or image — routes it through specialized analyzers via an AI-driven orchestration loop, and produces a professional PWNDoc report (JSON / PDF / HTML) summarizing all findings, risk scores, and actionable recommendations.

Built for security analysts and SOC teams who need a single platform instead of manually correlating results across multiple tools.

---

## Features

- **Auto-Pipeline** — Drop in any input and let SecFlow handle routing, analysis, and reporting automatically
- **Four Specialized Analyzers** — Malware, Steganography, Reconnaissance, and Web Vulnerability
- **AI-Driven Orchestration** — Gemini AI decides which analyzer runs next based on each pass's findings (AI tool-calling)
- **Smart First-Pass Classification** — Uses `file` + `python-magic` for deterministic routing before invoking AI
- **Configurable Loop Depth** — Run the analysis loop for 3, 4, or 5 passes; exits early if no further signals
- **Persistent Findings Store** — All output across every loop iteration is accumulated for the final report
- **PWNDoc Report Generation** — AI-formatted output in JSON, PDF, and HTML
- **Standalone Analyzer Mode** — Use any single analyzer independently

---

## How It Works

```
User Input (file / URL / IP / domain / image)
        │
        ▼
┌─────────────────────────────┐
│   Input Classifier          │  file command + python-magic
│   (Rule-based, no AI)       │  → if unknown type: Gemini fallback
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│   Analyzer Loop (N passes)  │  N = 3, 4, or 5 (user-configured)
│                             │
│  ┌────────────────────┐     │
│  │  Run Analyzer      │     │  Malware / Steg / Recon / Web
│  └────────┬───────────┘     │
│           │ output          │
│  ┌────────▼───────────┐     │
│  │  Gemini AI         │     │  Decides next analyzer
│  │  (Tool-Calling)    │     │  or terminates loop
│  └────────┬───────────┘     │
│           │ next tool       │
│           └────── repeat ───┘
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│   Findings Store            │  Aggregated output of all passes
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│   PWNDoc Report Generator   │  Gemini formats → JSON / PDF / HTML
└─────────────────────────────┘
```

---

## Analyzers

| Analyzer | Input Types | Focus |
|---|---|---|
| Malware | EXE, binary, PE, extracted payloads | Static/dynamic detection, YARA, strings |
| Steganography | PNG, JPG, BMP, images | Hidden data, embedded payloads |
| Reconnaissance | IPs, domains | OSINT, WHOIS, DNS, ports, ASN |
| Web Vulnerability | URLs, web endpoints | Headers, fingerprinting, vuln scanning |

---

## Example Run

```
Input: suspicious.png

Pass 1 — Rule triggers Steg Analyzer
         → Hidden EXE found embedded in image

Pass 2 — AI triggers Malware Analyzer
         → EXE makes HTTP callout to 192.168.1.100

Pass 3 — AI triggers Web Analyzer
         → Endpoint fingerprinted, vulnerabilities identified

Loop ends → Report generated (JSON + PDF + HTML)
```

---

## Project Structure

```
secflow/
├── backend/
│   ├── orchestrator/       # NEW — Flask pipeline loop (port 5000)
│   │   ├── app/
│   │   │   ├── routes.py           ← POST /api/smart-analyze
│   │   │   ├── orchestrator.py     ← Pipeline loop
│   │   │   ├── classifier/
│   │   │   ├── ai/
│   │   │   ├── adapters/           ← Translates analyzer responses
│   │   │   ├── store/
│   │   │   └── reporter/
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── malware-analyzer/   # Existing service (port 5001)
│   ├── steg-analyzer/      # Existing service (port 5002)
│   ├── recon-analyzer/     # Existing service (port 5003)
│   ├── url-analyzer/       # Existing service (port 5004, internal only)
│   ├── web-analyzer/       # Existing service (port 5005)
│   └── compose.yml         # Starts all 6 services on secflow-net
├── frontend/           # UI (planned — later phase)
├── docs/               # Architecture, pipeline flow, analyzer docs
├── ProjectDetails.md   # Full formatted project specification
├── AGENTS.md           # Agent definitions and coding instructions
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

## Status

> Backend pipeline is the current focus. Frontend UI is planned for a later phase.
