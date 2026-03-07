# SecFlow — Implementation Guide

This document is the hands-on engineering reference for building SecFlow's backend pipeline. It covers project structure, component-by-component implementation with code snippets, integration wiring, and a phased roadmap with in-depth milestones.

---

## Table of Contents

1. [Project Structure](#1-project-structure)
2. [Environment & Dependencies Setup](#2-environment--dependencies-setup)
3. [Implementation Order — Why It Matters](#3-implementation-order--why-it-matters)
4. [Findings Store](#4-findings-store)
5. [Input Classifier](#5-input-classifier)
6. [Malware Analyzer](#6-malware-analyzer)
7. [Steganography Analyzer](#7-steganography-analyzer)
8. [Reconnaissance Analyzer](#8-reconnaissance-analyzer)
9. [Web Vulnerability Analyzer](#9-web-vulnerability-analyzer)
10. [AI Decision Engine](#10-ai-decision-engine)
11. [Pipeline Orchestrator](#11-pipeline-orchestrator)
12. [Report Generator](#12-report-generator)
13. [Wiring It All Together](#13-wiring-it-all-together)
14. [Implementation Roadmap](#14-implementation-roadmap)

---

## 1. Project Structure

SecFlow uses a **microservices layout**. The five analyzer services run as independent Docker containers; the Orchestrator service coordinates them via HTTP.

```
backend/
├── orchestrator/                    ← NEW Docker service (port 5000)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes.py                ← Flask: POST /api/smart-analyze
│   │   ├── orchestrator.py          ← Pipeline loop (calls analyzers via HTTP)
│   │   ├── classifier/
│   │   │   ├── classifier.py
│   │   │   └── rules.py
│   │   ├── ai/
│   │   │   ├── engine.py
│   │   │   └── keywords.txt
│   │   ├── adapters/                ← Translate analyzer JSON → SecFlow contract
│   │   │   ├── malware_adapter.py
│   │   │   ├── steg_adapter.py
│   │   │   ├── recon_adapter.py
│   │   │   ├── url_adapter.py
│   │   │   └── web_adapter.py
│   │   ├── store/
│   │   │   └── findings_store.py
│   │   └── reporter/
│   │       ├── report_generator.py
│   │       └── pwndoc_schema.json
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env.example
│
├── malware-analyzer/                ← Analyzer microservice (Docker, port 5001)
├── steg-analyzer/                   ← Analyzer microservice (Docker, port 5002)
├── recon-analyzer/                  ← Analyzer microservice (Docker, port 5003)
├── url-analyzer/                    ← Analyzer microservice (Docker, port 5004, internal)
├── web-analyzer/                    ← Analyzer microservice (Docker, port 5005)
│
└── compose.yml                      ← Wires all 6 services on secflow-net

docs/
├── architecture.md
├── pipeline-flow.md
├── analyzers.md
├── implementation-guide.md
└── migration.md

tests/
├── test_classifier.py
├── test_adapters.py
├── test_ai_engine.py
├── test_store.py
└── test_orchestrator.py

.env.example
```

The key rule: **never import analyzer code directly into the Orchestrator**. Always call analyzers via `requests.post()` to their Docker service URL.

Run this to scaffold it all at once:

```bash
mkdir -p backend/{orchestrator,classifier,ai,analyzers/{malware,steg,recon,web},store,reporter} tests
touch backend/__init__.py
for d in orchestrator classifier ai analyzers analyzers/malware analyzers/steg analyzers/recon analyzers/web store reporter; do
  touch backend/$d/__init__.py
done
touch backend/analyzers/base.py
touch backend/orchestrator/orchestrator.py
touch backend/classifier/{classifier.py,rules.py}
touch backend/ai/{engine.py,keywords.txt}
touch backend/analyzers/{malware,steg,recon,web}/analyzer.py
touch backend/store/findings_store.py
touch backend/reporter/{report_generator.py,pwndoc_schema.json}
touch requirements.txt .env.example
```

---

## 2. Environment & Dependencies Setup

### `.env.example`
```
GEMINI_API_KEY=your_gemini_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here       # optional
VIRUSTOTAL_API_KEY=your_vt_api_key_here       # optional
```

### `requirements.txt`
```
# Core
python-dotenv>=1.0.0
google-generativeai>=0.5.0

# Classification
python-magic>=0.4.27

# Malware Analyzer
yara-python>=4.3.1
pefile>=2023.2.7

# Steganography Analyzer
Pillow>=10.0.0
pyexiftool>=0.5.6

# Recon Analyzer
python-whois>=0.9.4
dnspython>=2.4.2
python-nmap>=0.7.1
shodan>=1.28.0

# Web Analyzer
requests>=2.31.0
sslyze>=5.2.0

# Reporting
fpdf2>=2.7.6
jinja2>=3.1.2

# Dev
black>=24.0.0
ruff>=0.3.0
pytest>=8.0.0
```

### Bootstrap script
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your actual keys
```

### Loading env vars (use at the top of `orchestrator.py`):
```python
from dotenv import load_dotenv
load_dotenv()
```

---

## 3. Implementation Order — Why It Matters

Build bottom-up so every layer can be tested before the next depends on it:

```
1. Findings Store          ← no dependencies, everything else uses it
2. Analyzer Base           ← type definitions shared by all 4 analyzers
3. Four Analyzers          ← each independently testable
4. Input Classifier        ← depends on python-magic + rules only
5. AI Decision Engine      ← depends on Gemini API + keywords.txt
6. Pipeline Orchestrator   ← wires everything together
7. Report Generator        ← depends on Gemini + Findings Store
```

Test each component standalone before moving on. Each analyzer has a `run()` you can call directly from a script.

---

## 4. Findings Store

**File:** `backend/store/findings_store.py`

The simplest component — an ordered list with thread-safe appending and JSON serialization.

```python
import json
import threading
from typing import Any


class FindingsStore:
    """Accumulates analyzer outputs across all loop passes."""

    def __init__(self) -> None:
        self._findings: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def append(self, finding: dict[str, Any]) -> None:
        with self._lock:
            self._findings.append(finding)

    def get_all(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._findings)

    def to_json(self) -> str:
        return json.dumps(self.get_all(), indent=2)

    def is_empty(self) -> bool:
        return len(self._findings) == 0

    def last(self) -> dict[str, Any] | None:
        findings = self.get_all()
        return findings[-1] if findings else None

    def save_to_disk(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.to_json())
```

**Quick test:**
```python
store = FindingsStore()
store.append({"analyzer": "steg", "pass": 1, "findings": [], "risk_score": 5.0})
print(store.to_json())
```

---

## 5. Input Classifier

**Files:** `backend/classifier/classifier.py`, `backend/classifier/rules.py`

### `rules.py` — Deterministic routing rules

```python
import re

# Maps (condition_fn) → analyzer_name
# condition_fn receives (mime_type: str, magic_output: str, raw_input: str) → bool

RULES: list[tuple] = [
    # Images → Steg
    (lambda mime, magic, raw: mime.startswith("image/"), "steg"),

    # Executables / PE binaries → Malware
    (lambda mime, magic, raw: mime in (
        "application/x-executable",
        "application/x-dosexec",
        "application/x-msdos-program",
        "application/x-elf",
        "application/vnd.microsoft.portable-executable",
    ), "malware"),
    (lambda mime, magic, raw: "PE32" in magic or "ELF" in magic or "Mach-O" in magic, "malware"),

    # URLs → Web
    (lambda mime, magic, raw: bool(re.match(r'^https?://', raw.strip())), "web"),

    # IP addresses → Recon
    (lambda mime, magic, raw: bool(re.match(
        r'^\d{1,3}(\.\d{1,3}){3}$', raw.strip()
    )), "recon"),

    # Domains → Recon
    (lambda mime, magic, raw: bool(re.match(
        r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', raw.strip()
    )), "recon"),
]


def apply_rules(mime_type: str, magic_output: str, raw_input: str) -> str | None:
    """Return analyzer name if a rule matches, else None."""
    for condition, analyzer in RULES:
        if condition(mime_type, magic_output, raw_input):
            return analyzer
    return None
```

### `classifier.py` — Main classifier

```python
import subprocess
import magic  # python-magic
from pathlib import Path
from backend.classifier.rules import apply_rules


def classify(raw_input: str) -> tuple[str | None, str, str]:
    """
    Classify the input and return (analyzer_name | None, mime_type, magic_output).
    Returns None for analyzer_name if no rule matched (AI fallback needed).
    """
    mime_type = ""
    magic_output = ""

    path = Path(raw_input)
    if path.exists() and path.is_file():
        # It's a file — use python-magic
        mime_type = magic.from_file(str(path), mime=True)
        magic_output = magic.from_file(str(path))
    else:
        # It's a string (URL / IP / domain) — treat raw_input as the signal
        mime_type = "text/plain"
        magic_output = raw_input

    analyzer = apply_rules(mime_type, magic_output, raw_input)
    return analyzer, mime_type, magic_output


def get_file_head(file_path: str, lines: int = 100) -> str:
    """Return the first N lines of a file for AI fallback context."""
    try:
        result = subprocess.run(
            ["head", f"-{lines}", file_path],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except Exception:
        return ""
```

**Quick test:**
```python
analyzer, mime, magic_out = classify("/path/to/suspicious.png")
print(analyzer)   # "steg"

analyzer, mime, magic_out = classify("https://example.com")
print(analyzer)   # "web"

analyzer, mime, magic_out = classify("192.168.1.1")
print(analyzer)   # "recon"
```

---

## 6. Malware Analyzer

> **Note:** Do not modify the service code — write a `malware_adapter.py` instead. The snippet below is reference-only for understanding what the service does internally.

**Service endpoint:** `POST http://malware-analyzer:5001/api/malware-analyzer/` (file upload)

**File:** `backend/malware-analyzer/<main_module>.py`

```python
import hashlib
import subprocess
import re
from pathlib import Path
from typing import Any

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _compute_hashes(file_path: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    data = Path(file_path).read_bytes()
    for algo in ("md5", "sha1", "sha256"):
        hashes[algo] = hashlib.new(algo, data).hexdigest()
    return hashes


def _extract_strings(file_path: str, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from a binary."""
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), file_path],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.splitlines()
    except Exception:
        return []


def _flag_suspicious_strings(strings: list[str]) -> list[str]:
    patterns = [
        r'https?://',           # URLs
        r'\d{1,3}(\.\d{1,3}){3}',  # IPs
        r'cmd\.exe|powershell|bash',
        r'HKEY_',               # Registry keys
        r'CreateRemoteThread|VirtualAlloc|WriteProcessMemory',  # Dangerous API
        r'\.onion',             # Tor
    ]
    flagged = []
    for s in strings:
        for p in patterns:
            if re.search(p, s, re.IGNORECASE):
                flagged.append(s)
                break
    return flagged


def _run_yara(file_path: str, rules_dir: str = "backend/analyzers/malware/rules") -> list[str]:
    if not YARA_AVAILABLE:
        return []
    try:
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            return []
        rules = yara.compile(filepaths={
            f.stem: str(f) for f in rules_path.glob("*.yar")
        })
        matches = rules.match(file_path)
        return [str(m) for m in matches]
    except Exception as e:
        return [f"YARA error: {e}"]


def _parse_pe(file_path: str) -> dict[str, Any]:
    if not PEFILE_AVAILABLE:
        return {}
    try:
        pe = pefile.PE(file_path)
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports.append(entry.dll.decode(errors="replace"))
        return {
            "num_sections": len(pe.sections),
            "imports": imports,
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
        }
    except Exception as e:
        return {"error": str(e)}


# ── Entry Point ─────────────────────────────────────────────────────────────────

def run(input_data: str, pass_number: int) -> dict[str, Any]:
    findings: list[dict] = []
    raw_parts: list[str] = []

    try:
        # Hashes
        hashes = _compute_hashes(input_data)
        raw_parts.append(f"Hashes: {hashes}")
        findings.append({
            "type": "hash",
            "detail": f"MD5: {hashes['md5']}  SHA256: {hashes['sha256']}",
            "severity": "info",
            "evidence": str(hashes),
        })

        # YARA
        yara_matches = _run_yara(input_data)
        raw_parts.append(f"YARA: {yara_matches}")
        for match in yara_matches:
            findings.append({
                "type": "signature_match",
                "detail": f"YARA rule matched: {match}",
                "severity": "critical",
                "evidence": match,
            })

        # Strings
        strings = _extract_strings(input_data)
        suspicious = _flag_suspicious_strings(strings)
        raw_parts.append(f"Suspicious strings: {suspicious[:20]}")
        for s in suspicious[:20]:  # cap at 20 findings
            findings.append({
                "type": "suspicious_string",
                "detail": f"Suspicious pattern in strings: {s}",
                "severity": "high",
                "evidence": s,
            })

        # PE metadata
        pe_info = _parse_pe(input_data)
        if pe_info:
            raw_parts.append(f"PE metadata: {pe_info}")
            findings.append({
                "type": "pe_metadata",
                "detail": f"PE: {pe_info.get('num_sections')} sections, imports: {pe_info.get('imports', [])}",
                "severity": "medium" if pe_info.get("imports") else "low",
                "evidence": str(pe_info),
            })

    except Exception as e:
        findings.append({
            "type": "error",
            "detail": f"Malware analyzer error: {e}",
            "severity": "low",
            "evidence": str(e),
        })

    severity_weights = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}
    risk_score = min(10.0, sum(severity_weights.get(f["severity"], 0) for f in findings))

    return {
        "analyzer": "malware",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": "\n".join(raw_parts),
    }
```

---

## 7. Steganography Analyzer

> **Note:** Do not modify the service code — write a `steg_adapter.py` instead. The snippet below is reference-only for understanding what the service does internally.

**Service endpoint:** `POST http://steg-analyzer:5002/api/steg-analyzer/` (file upload)

**File:** `backend/steg-analyzer/<main_module>.py`

```python
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _run_tool(cmd: list[str], timeout: int = 30) -> str:
    """Run a system tool and return stdout+stderr, safe wrapper."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return f"[tool not found: {cmd[0]}]"
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"


def _run_binwalk(file_path: str, extract_dir: str) -> tuple[str, list[str]]:
    output = _run_tool(["binwalk", "--extract", "--directory", extract_dir, file_path])
    # Collect extracted files
    extracted = list(Path(extract_dir).rglob("*"))
    extracted_paths = [str(p) for p in extracted if p.is_file()]
    return output, extracted_paths


def _run_zsteg(file_path: str) -> str:
    return _run_tool(["zsteg", file_path])


def _run_exiftool(file_path: str) -> str:
    return _run_tool(["exiftool", file_path])


def _run_strings(file_path: str) -> list[str]:
    out = _run_tool(["strings", "-n", "8", file_path])
    return out.splitlines()


# ── Entry Point ─────────────────────────────────────────────────────────────────

def run(input_data: str, pass_number: int) -> dict[str, Any]:
    findings: list[dict] = []
    raw_parts: list[str] = []
    all_extracted: list[str] = []

    try:
        # binwalk — embedded file extraction
        with tempfile.TemporaryDirectory() as extract_dir:
            bw_output, extracted = _run_binwalk(input_data, extract_dir)
            raw_parts.append(f"binwalk:\n{bw_output}")
            if extracted:
                all_extracted.extend(extracted)
                findings.append({
                    "type": "embedded_file",
                    "detail": f"binwalk extracted {len(extracted)} file(s)",
                    "severity": "critical",
                    "evidence": "\n".join(extracted),
                    "extracted_path": extracted[0] if extracted else None,
                })

        # zsteg — PNG steganography
        if input_data.lower().endswith((".png",)):
            zsteg_out = _run_zsteg(input_data)
            raw_parts.append(f"zsteg:\n{zsteg_out}")
            if zsteg_out and "[tool not found" not in zsteg_out:
                findings.append({
                    "type": "lsb_data",
                    "detail": "zsteg detected steganographic content",
                    "severity": "high",
                    "evidence": zsteg_out[:500],
                    "extracted_path": None,
                })

        # exiftool — metadata inspection
        exif_out = _run_exiftool(input_data)
        raw_parts.append(f"exiftool:\n{exif_out}")
        suspicious_exif = ["gps", "creator", "comment", "warning"]
        for keyword in suspicious_exif:
            for line in exif_out.splitlines():
                if keyword.lower() in line.lower():
                    findings.append({
                        "type": "metadata_anomaly",
                        "detail": f"Suspicious metadata field: {line.strip()}",
                        "severity": "low",
                        "evidence": line.strip(),
                        "extracted_path": None,
                    })

    except Exception as e:
        findings.append({
            "type": "error",
            "detail": f"Steg analyzer error: {e}",
            "severity": "low",
            "evidence": str(e),
            "extracted_path": None,
        })

    severity_weights = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}
    risk_score = min(10.0, sum(severity_weights.get(f["severity"], 0) for f in findings))

    return {
        "analyzer": "steg",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": "\n".join(raw_parts),
        "extracted_files": all_extracted,
    }
```

---

## 8. Reconnaissance Analyzer

> **Note:** Do not modify the service code — write a `recon_adapter.py` instead. The snippet below is reference-only for understanding what the service does internally.

**Service endpoint:** `POST http://recon-analyzer:5003/api/recon-analyzer/` (JSON body)

**File:** `backend/recon-analyzer/<main_module>.py`

```python
import os
import socket
from typing import Any

import whois
import dns.resolver
import nmap


def _whois_lookup(target: str) -> tuple[str, list[dict]]:
    findings = []
    try:
        w = whois.whois(target)
        detail = f"Registrar: {w.registrar}, Created: {w.creation_date}, Expires: {w.expiration_date}"
        findings.append({
            "type": "whois",
            "detail": detail,
            "severity": "info",
            "evidence": str(w),
        })
        return str(w), findings
    except Exception as e:
        return str(e), []


def _dns_lookup(target: str) -> tuple[str, list[dict]]:
    results = []
    findings = []
    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = dns.resolver.resolve(target, record_type)
            for r in answers:
                results.append(f"{record_type}: {r}")
        except Exception:
            pass
    raw = "\n".join(results)
    if results:
        findings.append({
            "type": "dns",
            "detail": f"DNS records found: {len(results)} entries",
            "severity": "info",
            "evidence": raw,
        })
    return raw, findings


def _port_scan(target: str) -> tuple[str, list[dict]]:
    findings = []
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments="-F --open -T4")  # fast scan, open ports only
        open_ports = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                for port in scanner[host][proto].keys():
                    state = scanner[host][proto][port]["state"]
                    service = scanner[host][proto][port].get("name", "")
                    open_ports.append(f"{port}/{proto} {state} {service}")
        raw = "\n".join(open_ports)
        if open_ports:
            findings.append({
                "type": "port",
                "detail": f"{len(open_ports)} open port(s) detected",
                "severity": "medium" if len(open_ports) < 5 else "high",
                "evidence": raw,
            })
        return raw, findings
    except Exception as e:
        return str(e), []


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _shodan_lookup(target: str) -> tuple[str, list[dict]]:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return "", []
    try:
        import shodan
        api = shodan.Shodan(api_key)
        result = api.host(target)
        tags = result.get("tags", [])
        raw = str(result)
        severity = "critical" if any(t in tags for t in ("malware", "c2", "botnet")) else "medium"
        findings = [{
            "type": "threat_intel",
            "detail": f"Shodan: org={result.get('org')}, tags={tags}",
            "severity": severity,
            "evidence": raw[:500],
        }]
        return raw, findings
    except Exception as e:
        return str(e), []


# ── Entry Point ─────────────────────────────────────────────────────────────────

def run(input_data: str, pass_number: int) -> dict[str, Any]:
    findings: list[dict] = []
    raw_parts: list[str] = []

    try:
        raw, f = _whois_lookup(input_data)
        raw_parts.append(f"WHOIS:\n{raw}")
        findings.extend(f)

        raw, f = _dns_lookup(input_data)
        raw_parts.append(f"DNS:\n{raw}")
        findings.extend(f)

        raw, f = _port_scan(input_data)
        raw_parts.append(f"Ports:\n{raw}")
        findings.extend(f)

        rdns = _reverse_dns(input_data)
        if rdns:
            raw_parts.append(f"Reverse DNS: {rdns}")

        raw, f = _shodan_lookup(input_data)
        if raw:
            raw_parts.append(f"Shodan:\n{raw}")
            findings.extend(f)

    except Exception as e:
        findings.append({
            "type": "error",
            "detail": f"Recon analyzer error: {e}",
            "severity": "low",
            "evidence": str(e),
        })

    severity_weights = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}
    risk_score = min(10.0, sum(severity_weights.get(f["severity"], 0) for f in findings))

    return {
        "analyzer": "recon",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": "\n".join(raw_parts),
    }
```

---

## 9. Web Vulnerability Analyzer

> **Note:** Do not modify the service code — write a `web_adapter.py` instead. The snippet below is reference-only for understanding what the service does internally.

**Service endpoint:** `POST http://web-analyzer:5005/api/web-analyzer/` (JSON body)

**File:** `backend/web-analyzer/<main_module>.py`

```python
import os
import ssl
import socket
from urllib.parse import urlparse
from typing import Any

import requests


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DANGEROUS_HEADERS = [
    "Server",           # leaks server version
    "X-Powered-By",     # leaks tech stack
    "X-AspNet-Version",
]


def _http_probe(url: str) -> tuple[requests.Response | None, str, list[dict]]:
    findings = []
    try:
        resp = requests.get(
            url, timeout=15,
            allow_redirects=True,
            verify=True,
            headers={"User-Agent": "SecFlow-Scanner/1.0"}
        )
        raw = f"Status: {resp.status_code}\nHeaders: {dict(resp.headers)}\n"

        # Missing security headers
        for header in SECURITY_HEADERS:
            if header not in resp.headers:
                findings.append({
                    "type": "missing_header",
                    "detail": f"Missing security header: {header}",
                    "severity": "medium",
                    "evidence": "",
                })

        # Info-leaking headers
        for header in DANGEROUS_HEADERS:
            if header in resp.headers:
                findings.append({
                    "type": "info_leak",
                    "detail": f"Information-leaking header: {header}: {resp.headers[header]}",
                    "severity": "low",
                    "evidence": f"{header}: {resp.headers[header]}",
                })

        return resp, raw, findings
    except requests.exceptions.SSLError as e:
        return None, str(e), [{
            "type": "tls_issue",
            "detail": f"SSL error: {e}",
            "severity": "high",
            "evidence": str(e),
        }]
    except Exception as e:
        return None, str(e), [{
            "type": "error",
            "detail": f"HTTP probe error: {e}",
            "severity": "low",
            "evidence": str(e),
        }]


def _tls_check(hostname: str, port: int = 443) -> tuple[str, list[dict]]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as sock:
            cert = sock.getpeercert()
            protocol = sock.version()
            cipher = sock.cipher()
            raw = f"Protocol: {protocol}, Cipher: {cipher}, Subject: {cert.get('subject')}"

            if protocol in ("TLSv1", "TLSv1.1"):
                findings.append({
                    "type": "tls_issue",
                    "detail": f"Deprecated TLS version in use: {protocol}",
                    "severity": "high",
                    "evidence": raw,
                })
            else:
                findings.append({
                    "type": "tls_issue",
                    "detail": f"TLS OK: {protocol}",
                    "severity": "info",
                    "evidence": raw,
                })
            return raw, findings
    except Exception as e:
        return str(e), []


def _tech_fingerprint(resp: requests.Response) -> list[dict]:
    """Simple header-based tech detection — replace with Wappalyzer for production."""
    TECH_SIGNATURES = {
        "Server": {
            "apache": "Apache",
            "nginx": "nginx",
            "iis": "Microsoft IIS",
        },
        "X-Powered-By": {
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
        },
    }
    findings = []
    for header, sigs in TECH_SIGNATURES.items():
        value = resp.headers.get(header, "").lower()
        for keyword, tech_name in sigs.items():
            if keyword in value:
                findings.append({
                    "type": "tech_fingerprint",
                    "detail": f"Technology identified: {tech_name}",
                    "severity": "info",
                    "evidence": f"{header}: {resp.headers.get(header)}",
                })
    return findings


# ── Entry Point ─────────────────────────────────────────────────────────────────

def run(input_data: str, pass_number: int) -> dict[str, Any]:
    findings: list[dict] = []
    raw_parts: list[str] = []

    try:
        parsed = urlparse(input_data)
        hostname = parsed.hostname or input_data

        resp, raw, http_findings = _http_probe(input_data)
        raw_parts.append(f"HTTP:\n{raw}")
        findings.extend(http_findings)

        if resp is not None:
            tech_findings = _tech_fingerprint(resp)
            findings.extend(tech_findings)

        if parsed.scheme == "https" and hostname:
            tls_raw, tls_findings = _tls_check(hostname)
            raw_parts.append(f"TLS:\n{tls_raw}")
            findings.extend(tls_findings)

    except Exception as e:
        findings.append({
            "type": "error",
            "detail": f"Web analyzer error: {e}",
            "severity": "low",
            "evidence": str(e),
        })

    severity_weights = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}
    risk_score = min(10.0, sum(severity_weights.get(f["severity"], 0) for f in findings))

    return {
        "analyzer": "web",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": "\n".join(raw_parts),
    }
```

---

## 10. AI Decision Engine

**File:** `backend/ai/engine.py`

This is the brain. It takes analyzer output and uses Gemini to decide the next tool. It also handles the grep fallback.

```python
import os
import re
from pathlib import Path
from typing import Any

import google.generativeai as genai


# ── Setup ───────────────────────────────────────────────────────────────────────

genai.configure(api_key=os.environ["GEMINI_API_KEY"])
_model = genai.GenerativeModel("gemini-1.5-pro-latest")

ANALYZER_NAMES = ["malware", "steg", "recon", "web"]

KEYWORDS_FILE = Path(__file__).parent / "keywords.txt"


def _load_keywords() -> list[str]:
    if KEYWORDS_FILE.exists():
        return [line.strip() for line in KEYWORDS_FILE.read_text().splitlines() if line.strip()]
    return []


def _grep_keywords(text: str, keywords: list[str]) -> str:
    """Return lines from text that contain any keyword."""
    matched = []
    for line in text.splitlines():
        if any(kw.lower() in line.lower() for kw in keywords):
            matched.append(line)
    return "\n".join(matched)


def _build_prompt(
    analyzer_output: dict[str, Any],
    current_tool: str,
    pass_number: int,
    max_passes: int,
    context_text: str,
) -> str:
    available = [a for a in ANALYZER_NAMES if a != current_tool]
    return f"""You are a cybersecurity analysis AI.

A {current_tool} analyzer just ran on pass {pass_number} of {max_passes}.

Analyzer findings summary:
{context_text}

Available next analyzers: {available}

Based on the findings above, decide which analyzer to run next.
- If the findings suggest an extracted binary or executable → malware
- If findings contain a URL or HTTP endpoint → web
- If findings contain an IP address or domain → recon
- If findings contain an image file → steg
- If there is nothing meaningful to analyze further, or max passes reached → null

You MUST respond with ONLY a JSON object in this exact format:
{{
  "next_tool": "<analyzer_name or null>",
  "reasoning": "<one sentence explanation>"
}}
"""


# ── Main Decision Function ───────────────────────────────────────────────────────

def decide_next(
    analyzer_output: dict[str, Any],
    pass_number: int,
    max_passes: int,
) -> dict[str, str | None]:
    """
    Given the output of the most recent analyzer, return:
    { "next_tool": str | None, "reasoning": str }
    """
    current_tool = analyzer_output["analyzer"]
    raw_output = analyzer_output.get("raw_output", "")
    keywords = _load_keywords()

    # Strategy 1: use raw_output directly if reasonably sized
    context = raw_output if len(raw_output) <= 4000 else ""

    # Strategy 2: grep keywords if output is large
    if not context and raw_output:
        context = _grep_keywords(raw_output, keywords)

    # Strategy 3: fall back to full output (truncated) if grep gave nothing
    if not context:
        context = raw_output[:4000]

    prompt = _build_prompt(analyzer_output, current_tool, pass_number, max_passes, context)

    try:
        response = _model.generate_content(prompt)
        text = response.text.strip()

        # Parse JSON from Gemini response
        import json
        # Gemini sometimes wraps in ```json ... ```
        text = re.sub(r"^```json\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        result = json.loads(text)

        next_tool = result.get("next_tool")
        # Validate — only accept known analyzer names or null
        if next_tool not in ANALYZER_NAMES + [None, "null"]:
            next_tool = None
        if next_tool == "null":
            next_tool = None

        return {
            "next_tool": next_tool,
            "reasoning": result.get("reasoning", ""),
        }

    except Exception as e:
        return {
            "next_tool": None,
            "reasoning": f"AI decision failed: {e} — terminating loop.",
        }
```

### `keywords.txt` — seed content for the grep fallback

```
http://
https://
192.168.
10.0.
172.16.
.exe
.dll
.elf
.bin
payload
malware
trojan
c2
beacon
command and control
open port
vulnerability
CVE-
injection
xss
sqli
YARA
embedded
hidden
steg
reverse shell
shell code
```

---

## 11. Pipeline Orchestrator

**File:** `backend/orchestrator/orchestrator.py`

This is where all components wire together into the loop.

```python
import logging
from typing import Any

from backend.classifier.classifier import classify, get_file_head
from backend.ai.engine import decide_next
from backend.store.findings_store import FindingsStore
from backend.analyzers.malware import analyzer as malware_analyzer
from backend.analyzers.steg import analyzer as steg_analyzer
from backend.analyzers.recon import analyzer as recon_analyzer
from backend.analyzers.web import analyzer as web_analyzer

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("secflow.orchestrator")

ANALYZER_MAP = {
    "malware": malware_analyzer.run,
    "steg": steg_analyzer.run,
    "recon": recon_analyzer.run,
    "web": web_analyzer.run,
}


def _extract_next_input(last_finding: dict[str, Any], next_tool: str) -> str | None:
    """
    Extract the relevant input value for the next analyzer from the last findings.
    E.g. if next_tool is 'malware', look for extracted file paths in steg output.
    """
    findings = last_finding.get("findings", [])

    if next_tool == "malware":
        # Look for extracted files (from steg)
        extracted = last_finding.get("extracted_files", [])
        if extracted:
            return extracted[0]
        # Or look for file paths in finding evidence
        for f in findings:
            if f.get("type") == "embedded_file" and f.get("extracted_path"):
                return f["extracted_path"]

    if next_tool in ("recon", "web"):
        import re
        # Search raw output for IPs and URLs
        raw = last_finding.get("raw_output", "")
        if next_tool == "web":
            urls = re.findall(r'https?://[^\s"\'<>]+', raw)
            if urls:
                return urls[0]
        if next_tool == "recon":
            ips = re.findall(r'\b\d{1,3}(\.\d{1,3}){3}\b', raw)
            if ips:
                return ips[0]
            domains = re.findall(r'\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b', raw)
            if domains:
                return domains[0]

    # Default: reuse the last analyzer's input
    return last_finding.get("input")


def run_pipeline(
    user_input: str,
    max_passes: int = 3,
) -> FindingsStore:
    """
    Main pipeline entry point. Returns a populated FindingsStore.

    Args:
        user_input: file path, URL, IP, or domain
        max_passes: maximum number of analyzer loop iterations (3, 4, or 5)
    """
    store = FindingsStore()

    # ── Pass 1: Deterministic Classification ─────────────────────────────────
    log.info(f"Pass 1 — classifying input: {user_input}")
    first_analyzer, mime, magic_out = classify(user_input)

    if first_analyzer is None:
        # AI fallback for unknown type
        log.info("Unknown type — using AI for first-pass classification")
        file_head = get_file_head(user_input)
        # Build a synthetic "classifier output" to ask AI
        synthetic_output: dict[str, Any] = {
            "analyzer": "classifier",
            "pass": 0,
            "input": user_input,
            "findings": [],
            "risk_score": 0.0,
            "raw_output": f"MIME: {mime}\nmagic: {magic_out}\nfile head:\n{file_head}",
        }
        decision = decide_next(synthetic_output, pass_number=0, max_passes=max_passes)
        first_analyzer = decision["next_tool"]
        log.info(f"AI selected first analyzer: {first_analyzer} — {decision['reasoning']}")

    if first_analyzer is None:
        log.warning("Could not determine first analyzer. Aborting.")
        return store

    # ── Analyzer Loop ─────────────────────────────────────────────────────────
    current_tool = first_analyzer
    current_input = user_input

    for pass_num in range(1, max_passes + 1):
        log.info(f"Pass {pass_num} — running {current_tool} on: {current_input}")

        analyzer_fn = ANALYZER_MAP.get(current_tool)
        if not analyzer_fn:
            log.error(f"Unknown analyzer: {current_tool}")
            break

        result = analyzer_fn(current_input, pass_num)
        store.append(result)

        log.info(
            f"Pass {pass_num} complete — {len(result['findings'])} findings, "
            f"risk_score={result['risk_score']}"
        )

        if pass_num >= max_passes:
            log.info("Max passes reached. Ending loop.")
            break

        # ── AI Decision ───────────────────────────────────────────────────────
        decision = decide_next(result, pass_number=pass_num, max_passes=max_passes)
        log.info(f"AI decision: next={decision['next_tool']} — {decision['reasoning']}")

        if decision["next_tool"] is None:
            log.info("AI signalled loop termination. Ending early.")
            break

        next_input = _extract_next_input(result, decision["next_tool"])
        if next_input is None:
            log.warning("Could not extract input for next analyzer. Ending loop.")
            break

        current_tool = decision["next_tool"]
        current_input = next_input

    return store
```

**CLI entry point** — add to the end of `orchestrator.py` or as a separate `__main__.py`:

```python
if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    load_dotenv()

    parser = argparse.ArgumentParser(description="SecFlow Pipeline")
    parser.add_argument("--input", required=True, help="File path, URL, IP, or domain")
    parser.add_argument("--passes", type=int, default=3, choices=[3, 4, 5])
    parser.add_argument("--output", default="findings.json", help="Save findings to JSON file")
    args = parser.parse_args()

    store = run_pipeline(args.input, max_passes=args.passes)
    store.save_to_disk(args.output)
    print(f"Pipeline complete. {len(store.get_all())} passes recorded.")
    print(f"Findings saved to {args.output}")
```

---

## 12. Report Generator

**File:** `backend/reporter/report_generator.py`

```python
import os
import json
from pathlib import Path
from typing import Any

import google.generativeai as genai
from fpdf import FPDF
from jinja2 import Template

genai.configure(api_key=os.environ["GEMINI_API_KEY"])
_model = genai.GenerativeModel("gemini-1.5-pro-latest")

SCHEMA_PATH = Path(__file__).parent / "pwndoc_schema.json"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>SecFlow Report</title>
<style>
  body { font-family: monospace; background: #111; color: #eee; padding: 2rem; }
  h1 { color: #ff6b6b; } h2 { color: #ffd93d; }
  .finding { border: 1px solid #444; margin: 0.5rem 0; padding: 0.5rem; border-radius: 4px; }
  .critical { border-color: #ff0000; } .high { border-color: #ff8c00; }
  .medium { border-color: #ffd700; } .low { border-color: #4caf50; }
</style>
</head>
<body>
<h1>SecFlow Threat Report</h1>
<p>Input: {{ report.input }} | Total passes: {{ report.total_passes }} | Overall risk: {{ report.overall_risk_score }}/10</p>
<h2>Executive Summary</h2>
<p>{{ report.summary }}</p>
<h2>Findings Timeline</h2>
{% for pass in report.passes %}
<h3>Pass {{ pass.pass_number }} — {{ pass.analyzer }}</h3>
{% for f in pass.findings %}
<div class="finding {{ f.severity }}">
  <strong>[{{ f.type }}] {{ f.detail }}</strong><br>
  <code>{{ f.evidence }}</code>
</div>
{% endfor %}
{% endfor %}
<h2>Recommendations</h2>
<ul>{% for r in report.recommendations %}<li>{{ r }}</li>{% endfor %}</ul>
</body>
</html>
"""


def _ask_gemini_to_format(findings_json: str) -> dict[str, Any]:
    prompt = f"""You are a cybersecurity report writer.

Given the following raw analyzer findings from a multi-pass threat analysis pipeline,
produce a structured PWNDoc-compatible threat report.

Raw findings:
{findings_json}

Respond ONLY with a JSON object matching this structure:
{{
  "input": "the analyzed input",
  "total_passes": <number>,
  "overall_risk_score": <0.0-10.0>,
  "summary": "2-3 sentence executive summary",
  "passes": [
    {{
      "pass_number": 1,
      "analyzer": "steg",
      "findings": [...]
    }}
  ],
  "recommendations": ["actionable recommendation 1", "..."]
}}
"""
    response = _model.generate_content(prompt)
    text = response.text.strip()
    import re
    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


def generate_report(
    findings_json: str,
    output_dir: str = ".",
    base_name: str = "secflow_report",
) -> dict[str, str]:
    """
    Generate JSON, HTML, and PDF reports from findings JSON.
    Returns dict of { format: file_path }.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report_data = _ask_gemini_to_format(findings_json)

    # ── JSON ──────────────────────────────────────────────────────────────────
    json_path = output_path / f"{base_name}.json"
    json_path.write_text(json.dumps(report_data, indent=2))

    # ── HTML ──────────────────────────────────────────────────────────────────
    html_path = output_path / f"{base_name}.html"
    template = Template(HTML_TEMPLATE)
    html_content = template.render(report=type("R", (), report_data)())
    html_path.write_text(html_content)

    # ── PDF ───────────────────────────────────────────────────────────────────
    pdf_path = output_path / f"{base_name}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.set_title("SecFlow Threat Report")

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "SecFlow Threat Report", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.cell(0, 8, f"Overall Risk Score: {report_data.get('overall_risk_score')}/10", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(0, 6, report_data.get("summary", ""))
    pdf.ln(4)

    for pass_data in report_data.get("passes", []):
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, f"Pass {pass_data['pass_number']} — {pass_data['analyzer'].upper()}", ln=True)
        pdf.set_font("Helvetica", size=10)
        for finding in pass_data.get("findings", []):
            pdf.multi_cell(0, 5, f"[{finding.get('severity','').upper()}] {finding.get('detail','')}")
        pdf.ln(2)

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "Recommendations", ln=True)
    pdf.set_font("Helvetica", size=11)
    for rec in report_data.get("recommendations", []):
        pdf.multi_cell(0, 6, f"• {rec}")

    pdf.output(str(pdf_path))

    return {
        "json": str(json_path),
        "html": str(html_path),
        "pdf": str(pdf_path),
    }
```

---

## 13. Wiring It All Together

Here is the top-level script that ties orchestrator + reporter:

```python
# run_secflow.py  (at repo root)
import argparse
from dotenv import load_dotenv
load_dotenv()

from backend.orchestrator.orchestrator import run_pipeline
from backend.reporter.report_generator import generate_report

def main():
    parser = argparse.ArgumentParser(description="SecFlow — Automated Threat Analysis")
    parser.add_argument("--input", required=True, help="File path, URL, IP, or domain to analyze")
    parser.add_argument("--passes", type=int, default=3, choices=[3, 4, 5], help="Max loop passes")
    parser.add_argument("--output", default="./reports", help="Directory for report output")
    args = parser.parse_args()

    print(f"[*] Starting SecFlow on: {args.input}  (max {args.passes} passes)")
    store = run_pipeline(args.input, max_passes=args.passes)

    if store.is_empty():
        print("[!] No findings collected. Exiting.")
        return

    print(f"[*] {len(store.get_all())} passes collected. Generating report...")
    paths = generate_report(
        findings_json=store.to_json(),
        output_dir=args.output,
    )
    print("[+] Report generated:")
    for fmt, path in paths.items():
        print(f"    {fmt.upper()}: {path}")


if __name__ == "__main__":
    main()
```

**Usage:**
```bash
python run_secflow.py --input suspicious.png --passes 5 --output ./reports
python run_secflow.py --input "https://example.com" --passes 3
python run_secflow.py --input "192.168.1.100" --passes 4
```

---

## 14. Implementation Roadmap

SecFlow's implementation follows a **migration-first approach**: the five old analyzer services are kept exactly as-is. All new work lives in the Orchestrator service.

The roadmap is broken into 5 phases. Each phase produces independently testable output.

---

### Phase 1 — Copy & Verify Old Services (Week 1)

**Goal:** Move the five existing analyzer services into the new repo layout and confirm they all start and respond.

#### Milestones

| # | Task | Done When |
|---|---|---|
| 1.1 | Copy `malware-analyzer/`, `steg-analyzer/`, `recon-analyzer/`, `url-analyzer/`, `web-analyzer/` into `backend/` | `ls backend/` shows all 5 dirs |
| 1.2 | Write a minimal `compose.yml` that starts all 5 services | `docker compose up` — all 5 healthy |
| 1.3 | Smoke-test each service with `curl` | Returns JSON on its health / main route |
| 1.4 | Document each service's actual response JSON shape | Notes in `docs/migration.md` adapters section |
| 1.5 | Create `.env.example` for any keys the old services need | No service starts without required vars |

---

### Phase 2 — Write Adapters (Week 2)

**Goal:** For each analyzer service, write an adapter that normalises its native JSON response into the SecFlow contract.

#### Milestones

| # | Task | Done When |
|---|---|---|
| 2.1 | Inspect each service's actual response JSON (from Phase 1 notes) | Fields documented |
| 2.2 | Implement `malware_adapter.py` | Unit test passes with real service response sample |
| 2.3 | Implement `steg_adapter.py` | Unit test passes |
| 2.4 | Implement `recon_adapter.py` | Unit test passes |
| 2.5 | Implement `url_adapter.py` | Unit test passes |
| 2.6 | Implement `web_adapter.py` | Unit test passes |
| 2.7 | Write `tests/test_adapters.py` — feed recorded response JSON, assert output matches SecFlow contract | `pytest tests/test_adapters.py` passes |

#### SecFlow contract reminder
```python
{
    "analyzer": str,      # "malware" | "steg" | "recon" | "url" | "web"
    "pass": int,
    "input": str,
    "findings": list[dict],
    "risk_score": float,  # 0.0 – 10.0
    "raw_output": str
}
```

---

### Phase 3 — Build Orchestrator Core (Week 3)

**Goal:** Classifier, AI Decision Engine, and Findings Store are implemented and unit-tested.

#### Milestones

| # | Task | Done When |
|---|---|---|
| 3.1 | Create `orchestrator/` directory, scaffold Flask app (`__init__.py`, `routes.py`) | `flask run` shows no import errors |
| 3.2 | Implement `FindingsStore` | `append`, `get_all`, `to_json` unit tests pass |
| 3.3 | Implement `rules.py` — deterministic routing rules | PNG → steg, EXE → malware, URL → web, IP → recon |
| 3.4 | Implement `classifier.py` — `classify()` + `get_file_head()` | Returns correct first tool for 10 test inputs |
| 3.5 | Implement `engine.py` — Gemini prompt + response parsing | Returns `{next_tool, reasoning}` structure |
| 3.6 | Implement `engine.py` — keyword grep fallback | Engaged when `raw_output` > 4000 chars |
| 3.7 | Populate `keywords.txt` with 30+ relevant terms | Grep reduces noisy analyzer output |
| 3.8 | Unit test classifier rules and AI engine in isolation | `pytest tests/test_classifier.py tests/test_ai_engine.py` pass |

---

### Phase 4 — Pipeline Loop + Flask Route + Docker (Week 4)

**Goal:** `POST /api/smart-analyze` runs the full loop end-to-end, all 6 services in Docker Compose.

#### Milestones

| # | Task | Done When |
|---|---|---|
| 4.1 | Implement `orchestrator.py` — `run_pipeline()` with HTTP analyzer calls + adapter dispatch | Loop runs without crashing |
| 4.2 | Implement early termination on `next_tool: null` | Loop exits before max_passes when AI says done |
| 4.3 | Implement max_passes enforcement | Loop never exceeds user-configured value |
| 4.4 | Implement `routes.py` — `POST /api/smart-analyze` | Returns findings JSON in response |
| 4.5 | Add `orchestrator` service to `compose.yml` (6th service) | `docker compose up` — all 6 healthy |
| 4.6 | Write `orchestrator/Dockerfile` and `requirements.txt` | `docker compose build orchestrator` succeeds |
| 4.7 | End-to-end test: `suspicious.png` → 3 passes | JSON store has 3 entries, correct analyzer sequence |
| 4.8 | Test early exit: clean domain input → AI returns null at pass 2 | Store has 2 entries |

#### Critical transition test
```
Input: test_steg.png  (has embedded EXE that makes HTTP call)
Expected log:
  Pass 1 — steg-analyzer  — finds embedded exe
  AI decision → malware
  Pass 2 — malware-analyzer — finds HTTP URL
  AI decision → web
  Pass 3 — web-analyzer — scans endpoint
  AI decision → null (or max passes)
  Pipeline ends
```

---

### Phase 5 — Report Generator + Polish (Week 5)

**Goal:** PWNDoc reports generated. Pipeline is robust and production-ready.

#### Milestones

| # | Task | Done When |
|---|---|---|
| 5.1 | Define `pwndoc_schema.json` | Schema created, validates sample findings |
| 5.2 | Implement `report_generator.py` — Gemini formats findings → PWNDoc JSON | Report JSON returned |
| 5.3 | Implement JSON export | `report.json` written to disk |
| 5.4 | Implement HTML export with Jinja2 | `report.html` renders in browser |
| 5.5 | Implement PDF export with fpdf2 | `report.pdf` viewable |
| 5.6 | Validate schema before writing | Invalid Gemini output caught and logged |
| 5.7 | End-to-end test: full pipeline + all 3 report outputs | All 3 files created |
| 5.8 | Error handling audit: every HTTP call + tool call wrapped in try/except | No single failure crashes the pipeline |
| 5.9 | Write `tests/test_orchestrator.py` end-to-end integration test | `pytest` passes |
| 5.10 | Environment variable audit: no hardcoded secrets | `grep -r "API_KEY" backend/orchestrator/` finds only `os.getenv()` |

---

### Summary Timeline

```
Week 1 — Phase 1:  Copy old services, verify all start, document their response shapes
Week 2 — Phase 2:  Write all 5 adapters, unit-test against real response samples
Week 3 — Phase 3:  Build Orchestrator core (classifier, AI engine, findings store)
Week 4 — Phase 4:  Pipeline loop + Flask route + full Docker Compose
Week 5 — Phase 5:  Report generation + hardening + polish
```

---

### Quick-Reference: How to Test Each Component

```bash
# Test a single analyzer
python -c "from backend.analyzers.steg.analyzer import run; import json; print(json.dumps(run('test.png', 1), indent=2))"

# Test the classifier
python -c "from backend.classifier.classifier import classify; print(classify('test.png'))"

# Test the AI engine
python -c "
from backend.ai.engine import decide_next
result = decide_next({
    'analyzer': 'steg', 'pass': 1, 'input': 'x.png',
    'findings': [{'type': 'embedded_file', 'detail': 'EXE found'}],
    'risk_score': 8.0,
    'raw_output': 'PE32 executable found at /tmp/payload.exe'
}, pass_number=1, max_passes=3)
print(result)
"

# Run the full pipeline
python run_secflow.py --input suspicious.png --passes 3 --output ./reports
```
