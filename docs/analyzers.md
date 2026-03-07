# SecFlow — Analyzers

This document specifies each of SecFlow's four analyzers: their purpose, inputs, outputs, planned tools, and expected findings.

---

## Common Interface

Each analyzer is an **independent Docker microservice**. The Orchestrator never imports analyzer code — it always calls via HTTP.

| Analyzer | Docker service | Port | Transport | Input |
|---|---|---|---|---|
| Malware | `malware-analyzer` | 5001 | `multipart/form-data` | Binary file |
| Steganography | `steg-analyzer` | 5002 | `multipart/form-data` | Image file |
| Reconnaissance | `recon-analyzer` | 5003 | JSON `{"target": "..."}` | IP or domain |
| URL (internal) | `url-analyzer` | 5004 | JSON `{"url": "..."}` | URL (no public route) |
| Web Vulnerability | `web-analyzer` | 5005 | JSON `{"url": "..."}` | URL |

Each service returns its own native JSON. An **adapter** inside the Orchestrator (`orchestrator/app/adapters/<name>_adapter.py`) translates that into the SecFlow contract:

```python
{
    "analyzer": str,         # "malware" | "steg" | "recon" | "url" | "web"
    "pass": int,             # 1-indexed loop pass number
    "input": str,            # the exact value passed in
    "findings": list[dict],  # see per-analyzer finding format below
    "risk_score": float,     # aggregate risk for this pass, 0.0–10.0
    "raw_output": str        # concatenated raw tool output (for AI consumption)
}
```

Analyzer services must **never crash the Orchestrator**. The adapter must wrap the HTTP call in try/except and return an error-shaped finding dict if the service is unreachable or returns a non-200 response.

---

## 1. Malware Analyzer

**Service:** `backend/malware-analyzer/` — `POST http://malware-analyzer:5001/api/malware-analyzer/`
**Adapter:** `orchestrator/app/adapters/malware_adapter.py`

### Purpose
Detect malicious characteristics in executables, PE binaries, and extracted binary payloads.

### Accepted Input
- File path to: `.exe`, `.dll`, `.bin`, `.elf`, extracted payload from another analyzer pass

### Analysis Techniques
| Technique | Description |
|---|---|
| File hashing | Compute MD5, SHA1, SHA256 |
| YARA scanning | Match bundled YARA rule set |
| PE header analysis | Parse PE sections, imports, exports, timestamps |
| String extraction | Extract printable strings; flag suspicious patterns (URLs, IPs, registry keys, API names) |
| Entropy analysis | High entropy sections → possible packing/encryption |
| (Optional) VirusTotal | Hash lookup via VT API if key is configured |

### Finding Object Format
```python
{
    "type": "signature_match" | "suspicious_string" | "pe_metadata" | "hash" | "entropy" | "error",
    "detail": str,     # human-readable description
    "severity": "low" | "medium" | "high" | "critical",
    "evidence": str    # raw evidence snippet
}
```

### Example Findings
```json
[
  { "type": "hash", "detail": "SHA256: abc123...", "severity": "info", "evidence": "" },
  { "type": "signature_match", "detail": "YARA rule: Trojan.GenericKDZ matched", "severity": "critical", "evidence": "offset 0x200" },
  { "type": "suspicious_string", "detail": "HTTP callout found", "severity": "high", "evidence": "http://192.168.1.100/beacon" }
]
```

### Planned Libraries
- `yara-python` — YARA rule matching
- `pefile` — PE binary parsing
- `hashlib` — File hashing (stdlib)
- `strings` (system) or regex — String extraction

---

## 2. Steganography Analyzer

**Service:** `backend/steg-analyzer/` — `POST http://steg-analyzer:5002/api/steg-analyzer/`
**Adapter:** `orchestrator/app/adapters/steg_adapter.py`

### Purpose
Detect and extract hidden data embedded within image files using steganographic or watermarking techniques.

### Accepted Input
- File path to: `.png`, `.jpg`, `.jpeg`, `.bmp`, `.gif`, `.tiff`

### Analysis Techniques
| Technique | Description |
|---|---|
| LSB analysis | Detect least-significant-bit encoding in pixel data |
| Metadata inspection | ExifTool — check for hidden data in EXIF/IPTC/XMP |
| Embedded file extraction | binwalk — detect and extract appended/embedded files |
| Tool-based detection | zsteg (PNG), stegdetect (JPEG), steghide (JPEG/BMP) |
| Strings scan | Run strings on the image binary, flag suspicious patterns |

### Finding Object Format
```python
{
    "type": "embedded_file" | "lsb_data" | "metadata_anomaly" | "suspicious_string" | "error",
    "detail": str,
    "severity": "low" | "medium" | "high" | "critical",
    "evidence": str,
    "extracted_path": str | None   # path to extracted file if applicable
}
```

### Example Findings
```json
[
  { "type": "embedded_file", "detail": "binwalk found embedded PE binary", "severity": "critical", "evidence": "offset 0x8200", "extracted_path": "/tmp/secflow/extracted/steg_payload.exe" },
  { "type": "metadata_anomaly", "detail": "EXIF GPS data present", "severity": "low", "evidence": "GPS: 37.7749,-122.4194", "extracted_path": null }
]
```

### Planned Tools/Libraries
- `binwalk` (system) — File carving, embedded file extraction
- `zsteg` (system/gem) — PNG steg detection
- `stegdetect` (system) — JPEG steg detection
- `steghide` (system) — Steghide extraction
- `pyexiftool` or `exiftool` (system) — Metadata inspection
- `Pillow` — Image loading and pixel-level analysis

---

## 3. Reconnaissance Analyzer

**Service:** `backend/recon-analyzer/` — `POST http://recon-analyzer:5003/api/recon-analyzer/`
**Adapter:** `orchestrator/app/adapters/recon_adapter.py`

### Purpose
Gather OSINT and infrastructure intelligence on IPs, domains, and hostnames.

### Accepted Input
- IP address string (e.g., `"192.168.1.100"`)
- Domain or hostname string (e.g., `"evil.example.com"`)

### Analysis Techniques
| Technique | Description |
|---|---|
| WHOIS lookup | Registrant, registrar, creation/expiry dates |
| DNS records | A, AAAA, MX, NS, TXT, CNAME records |
| Reverse DNS | PTR record lookup |
| Port scanning | Top ports scan via nmap |
| Geolocation | Country, ASN, ISP |
| Threat intel | Shodan lookup (optional), AbuseIPDB (optional) |
| Certificate info | TLS cert subjects and SANs (for domains) |

### Finding Object Format
```python
{
    "type": "whois" | "dns" | "port" | "geolocation" | "threat_intel" | "cert" | "error",
    "detail": str,
    "severity": "info" | "low" | "medium" | "high" | "critical",
    "evidence": str
}
```

### Example Findings
```json
[
  { "type": "port", "detail": "Open ports detected", "severity": "medium", "evidence": "22/tcp open ssh, 80/tcp open http, 443/tcp open https" },
  { "type": "threat_intel", "detail": "IP found in Shodan with malware tag", "severity": "critical", "evidence": "tags: malware, c2" },
  { "type": "whois", "detail": "Domain registered 2 days ago", "severity": "high", "evidence": "created: 2026-03-04" }
]
```

### Planned Libraries/Tools
- `python-whois` — WHOIS lookups
- `dnspython` — DNS queries
- `nmap` (system) + `python-nmap` — Port scanning
- `shodan` — Shodan API (optional; requires `SHODAN_API_KEY`)
- `requests` — AbuseIPDB / threat intel APIs
- `socket` — Reverse DNS

---

## 4. Web Vulnerability Analyzer

**Service:** `backend/web-analyzer/` — `POST http://web-analyzer:5005/api/web-analyzer/`
**Adapter:** `orchestrator/app/adapters/web_adapter.py`

### Purpose
Analyze URLs and web endpoints for vulnerabilities, misconfigurations, and security weaknesses.

### Accepted Input
- Full URL string (e.g., `"http://192.168.1.100/beacon"`, `"https://example.com/login"`)

### Analysis Techniques
| Technique | Description |
|---|---|
| HTTP response analysis | Status code, response headers, redirect chain |
| Security header audit | Check for missing CSP, HSTS, X-Frame-Options, etc. |
| Technology fingerprinting | Identify server, framework, CMS versions |
| Cookie security | Inspect Secure, HttpOnly, SameSite flags |
| Basic vuln scanning | nuclei (optional), common path probing |
| TLS/SSL inspection | Certificate validity, weak ciphers |
| URL reputation | VirusTotal URL scan (optional) |

### Finding Object Format
```python
{
    "type": "missing_header" | "vuln" | "tech_fingerprint" | "tls_issue" | "redirect" | "cookie" | "error",
    "detail": str,
    "severity": "info" | "low" | "medium" | "high" | "critical",
    "evidence": str
}
```

### Example Findings
```json
[
  { "type": "missing_header", "detail": "Content-Security-Policy header absent", "severity": "medium", "evidence": "" },
  { "type": "tech_fingerprint", "detail": "Apache 2.4.49 detected (known CVE)", "severity": "critical", "evidence": "Server: Apache/2.4.49" },
  { "type": "tls_issue", "detail": "TLS 1.0 supported (deprecated)", "severity": "high", "evidence": "TLSv1.0 cipher accepted" }
]
```

### Planned Libraries/Tools
- `requests` — HTTP requests and response analysis
- `Wappalyzer` (or `builtwith`) — Technology fingerprinting
- `nuclei` (system, optional) — Template-based vuln scanning
- `sslyze` or `ssl` (stdlib) — TLS/SSL analysis
- `urllib` (stdlib) — URL parsing

---

## Risk Score Calculation

Each analyzer computes a `risk_score` (0.0–10.0) for the pass based on the severity distribution of its findings:

| Severity | Weight |
|---|---|
| `critical` | 4.0 |
| `high` | 2.5 |
| `medium` | 1.0 |
| `low` | 0.3 |
| `info` | 0.0 |

Score = min(10.0, sum of severity weights)

The Report Generator computes an **overall risk score** as the maximum risk score observed across all passes.

---

## Adding a New Analyzer

1. Create a new Docker service directory under `backend/<name>-analyzer/` with its own `Dockerfile` and `requirements.txt`.
2. Add the service to `backend/compose.yml` on the `secflow-net` network.
3. Create `orchestrator/app/adapters/<name>_adapter.py` to translate the service's native response into the SecFlow contract.
4. Add the analyzer name to the routing rules in `orchestrator/app/classifier/rules.py`.
5. Add the analyzer name to the available tools list in `orchestrator/app/ai/engine.py`.
6. Document the service and its endpoint in this file.
