# SecFlow — Project Details

> **Implementation status:** the active orchestrator is the TypeScript/LangGraph
> service in `backend/orchestrator-ts/`, using OpenRouter. The analyzer services
> remain Python/Flask. This document describes the product design; where an
> older implementation detail is mentioned below, the current source code and
> [docs/architecture.md](docs/architecture.md) take precedence.

## 1. Overview

**SecFlow** is a fully automated, end-to-end threat analysis pipeline with integrated PWNDoc reporting. It targets security analysts and SOC teams who currently deal with fragmented tooling, manually correlating data from multiple sources to investigate threats. This fragmentation slows incident response and increases the risk of missing critical indicators.

SecFlow solves this by accepting any input — file, URL, IP, domain, or image — and routing it through specialized analyzers via an intelligent AI-driven Pipeline Orchestrator. Findings from all analyzers are aggregated and rendered into a single, industry-grade PWNDoc report (JSON / HTML, with browser print-to-PDF), giving analysts instant visibility into threats, risk scores, and actionable recommendations.

**Theme Alignment:** Threat Detection and Incident Response.

---

## 2. Core Concept — The Factory Model

> "One file enters, multiple robots (workers) analyze it, and a printer at the end spits out the dossier."

SecFlow operates as an automated analysis factory:

| Stage | Description |
|---|---|
| **Input** | User submits a file, URL, IP, domain, or image |
| **Classification** | File type is identified; determines the first analyzer to invoke |
| **Analyzer Loop** | Analyzers are called iteratively (3–5 passes) guided by AI tool-calling |
| **Findings Store** | Outputs from every analyzer pass are accumulated in a persistent findings store |
| **Report Generation** | Aggregated findings are formatted by AI into a PWNDoc report (JSON / HTML) |

---

## 3. Analyzers

SecFlow has five specialized analyzers. They can be used individually or as part of the full automated pipeline.

| Analyzer | Primary Input | What It Does |
|---|---|---|
| **Malware Analyzer** | EXE, binary, PE files, extracted payloads | Static/dynamic malware detection, hash lookups, string extraction, behavioral indicators |
| **Steganography Analyzer** | PNG, JPG, BMP, and other image formats | Detects hidden/embedded data (payloads, text, files) within image files |
| **Reconnaissance Analyzer** | IPs, domains, hostnames | OSINT, WHOIS, DNS, port scanning, geolocation, ASN lookups |
| **Web Vulnerability Analyzer** | URLs, web endpoints | HTTP analysis, header inspection, vuln scanning, tech fingerprinting |

---

## 4. Pipeline Orchestration — How It Works

### 4.1 Input Classification (First Run — No AI)

On the very first pass, SecFlow avoids AI overhead by using deterministic rules:

- **Tool used:** magic-byte sniffing + MIME/extension rules in the TypeScript classifier
- **Rules example:**
  - Image (PNG, JPG, BMP…) → invoke **Steg Analyzer**
  - Office/RTF document → invoke **Macro Analyzer**
  - Executable / PE / ELF / Mach-O binary → invoke **Malware Analyzer**
  - URL string → invoke **Web Analyzer**
  - IP / domain / email / phone string → invoke **Recon Analyzer**
- **Unknown type fallback:** expose the applicable analyzer tools to the model and include a bounded, untrusted file-head preview in the decision prompt.

### 4.2 AI-Driven Loop (Subsequent Passes)

After each analyzer run, bounded findings and evidence references are passed to
the configured OpenRouter model, which selects the next validated analyzer tool
(`targetId` only) or returns `finish`. The model cannot supply arbitrary URLs,
paths, commands, or analyzer endpoints. Evidence comes from the run-scoped
raw-output store rather than unbounded dumps.

### 4.3 Loop Termination

- The loop runs for a user-configured maximum of **3, 4, or 5 passes**.
- If no further actionable findings exist before the max passes are reached, the loop terminates early.

### 4.4 Walk-Through Example

```
Input: suspicious.png

Pass 1 → Rule: image → Steg Analyzer
         Output: embedded EXE found inside PNG

Pass 2 → AI sees EXE → calls Malware Analyzer
         Output: EXE makes HTTP callout to 192.168.1.100

Pass 3 → AI sees IP/HTTP → calls Web Analyzer
         Output: endpoint fingerprinted, vulnerabilities found

Loop ends (3 passes reached / no more signals).

Report generated from all 3 passes → PWNDoc (JSON + HTML, PDF via browser print)
```

---

## 5. Findings Store

All analyzer outputs and intermediate AI decisions are written to a **persistent findings store** throughout every loop iteration. This accumulated context is what gets fed into the final report generation step.

---

## 6. Report Generation (PWNDoc)

At the end of the loop:
1. Aggregated findings from graph state are passed to the OpenRouter model.
2. The model formats narrative text into a structured PWNDoc-compatible report.
3. Output formats: **JSON**, **HTML** (PDF via the report's browser print button).

The report includes:
- Threat summary per analyzer
- Risk scores
- Actionable recommendations
- Full findings timeline across loop passes

---

## 7. Tech Stack

| Layer | Technology |
|---|---|
| **Service Orchestration** | Docker, Docker Compose |
| **API Framework** | Flask (Python 3.11+) |
| **File Classification** | Magic bytes + MIME/extension rules (TypeScript) |
| **AI Orchestration** | OpenRouter via Vercel AI SDK + LangGraph.js |
| **Malware Analysis** | Analyzer microservice — YARA, pefile, strings, hashlib |
| **Steganography** | Analyzer microservice — binwalk, zsteg, steghide, ExifTool |
| **Reconnaissance** | Analyzer microservice — nmap, WHOIS, dnspython, Shodan |
| **URL Analysis** | Analyzer microservice — internal only, no public route |
| **Web Vulnerability** | Analyzer microservice — requests, Wappalyzer |
| **Reporting** | PWNDoc — self-contained HTML + JSON (browser print-to-PDF) |
| **Frontend** | TBD (planned for later phase) |

---

## 8. User Interaction Modes

| Mode | Description |
|---|---|
| **Single Analyzer** | User picks one specific analyzer and runs it directly |
| **Full Auto-Pipeline** | User submits any input; the full loop runs automatically for N passes |

---

## 9. Project Goals

- Reduce manual correlation effort for security analysts and SOC teams
- Provide a single-platform, multi-vector threat analysis experience
- Generate polished, industry-standard PWNDoc reports automatically
- Enable faster threat detection and smarter incident response

---

## 10. Out of Scope (Current Phase)

- Frontend UI (planned separately, to be built after backend pipeline is stable)
- Real-time streaming of analyzer results
- Multi-user / authentication system
