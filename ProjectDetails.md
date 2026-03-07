# SecFlow — Project Details

## 1. Overview

**SecFlow** is a fully automated, end-to-end threat analysis pipeline with integrated PWNDoc reporting. It targets security analysts and SOC teams who currently deal with fragmented tooling, manually correlating data from multiple sources to investigate threats. This fragmentation slows incident response and increases the risk of missing critical indicators.

SecFlow solves this by accepting any input — file, URL, IP, domain, or image — and routing it through specialized analyzers via an intelligent AI-driven Pipeline Orchestrator. Findings from all analyzers are aggregated and rendered into a single, industry-grade PWNDoc report (JSON / PDF / HTML), giving analysts instant visibility into threats, risk scores, and actionable recommendations.

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
| **Report Generation** | Aggregated findings are formatted by AI into a PWNDoc report (JSON / PDF / HTML) |

---

## 3. Analyzers

SecFlow has four specialized analyzers. They can be used individually or as part of the full automated pipeline.

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

- **Tool used:** `file` command + `python-magic` library
- **Rules example:**
  - Image (PNG, JPG, BMP…) → invoke **Steg Analyzer**
  - Executable / PE binary → invoke **Malware Analyzer**
  - URL string → invoke **Web Analyzer**
  - IP / domain string → invoke **Recon Analyzer**
- **Unknown type fallback:** Pass `file`/`python-magic` output + first 100 lines (`head -100`) into **Gemini AI** to determine the first analyzer.

### 4.2 AI-Driven Loop (Subsequent Passes)

After each analyzer run, the output is fed into Gemini AI, which decides the next analyzer to call based on what was found. This is **AI tool-calling** — Gemini acts as an orchestrator that selects the next tool/worker.

**Fallback within AI decision:**
- If Gemini lacks enough context → pass the full analyzer output to Gemini
- If output is too noisy → grep through a predefined keyword list; pass matched snippets into Gemini for a focused decision

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

Report generated from all 3 passes → PWNDoc (JSON + PDF + HTML)
```

---

## 5. Findings Store

All analyzer outputs and intermediate AI decisions are written to a **persistent findings store** throughout every loop iteration. This accumulated context is what gets fed into the final report generation step.

---

## 6. Report Generation (PWNDoc)

At the end of the loop:
1. Aggregated findings from the store are passed to Gemini AI.
2. Gemini formats the findings into a structured PWNDoc-compatible report.
3. Output formats: **JSON**, **PDF**, **HTML**.

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
| **File Classification** | `file` (system command), `python-magic` |
| **AI Orchestration** | Google Gemini API (tool-calling) |
| **Malware Analysis** | Analyzer microservice — YARA, pefile, strings, hashlib |
| **Steganography** | Analyzer microservice — binwalk, zsteg, steghide, ExifTool |
| **Reconnaissance** | Analyzer microservice — nmap, WHOIS, dnspython, Shodan |
| **URL Analysis** | Analyzer microservice — internal only, no public route |
| **Web Vulnerability** | Analyzer microservice — requests, Wappalyzer |
| **Reporting** | PWNDoc — fpdf2 (PDF), Jinja2 (HTML), JSON |
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
