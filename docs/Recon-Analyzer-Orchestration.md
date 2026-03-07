# SecFlow — Recon Analyzer ↔ Orchestrator Integration

This document covers everything needed to wire the existing `Recon-Analyzer` service into the SecFlow pipeline. It is based on the **actual source code** in `backend/Recon-Analyzer/` — not the generic placeholder docs.

---

## Table of Contents

1. [What the Recon Analyzer Actually Does](#1-what-the-recon-analyzer-actually-does)
2. [Real API Endpoints](#2-real-api-endpoints)
3. [Exact Response Shapes](#3-exact-response-shapes)
4. [Port Mapping for SecFlow](#4-port-mapping-for-secflow)
5. [Dockerfile Considerations](#5-dockerfile-considerations)
6. [Environment Variables](#6-environment-variables)
7. [Which Endpoint the Orchestrator Should Call](#7-which-endpoint-the-orchestrator-should-call)
8. [Writing `recon_adapter.py`](#8-writing-recon_adapterpy)
9. [Updating `compose.yml`](#9-updating-composeyml)
10. [Classifier Rule for Recon](#10-classifier-rule-for-recon)
11. [Input Extraction Between Passes](#11-input-extraction-between-passes)
12. [Known Issues and Fixes](#12-known-issues-and-fixes)
13. [Step-by-Step Integration Checklist](#13-step-by-step-integration-checklist)

---

## 1. What the Recon Analyzer Actually Does

The existing `Recon-Analyzer` is a lightweight Flask service that performs **threat intelligence and OSINT** in two distinct modes depending on the input type:

### Mode 1 — Scan (IP / Domain)

| Module | File | Data Source | What it returns |
|---|---|---|---|
| IP Geolocation | `attack/ipapi.py` | `ip-api.com` batch API | Country, ISP, ASN, region, timezone |
| Talos Blocklist | `attack/talos.py` | Cisco Talos IP blocklist (local file, auto-downloaded from snort.org) | `blacklisted: true/false` |
| Tor Exit Nodes | `attack/tor.py` | Tor Project exit list (local file, auto-downloaded from torproject.org) | `is_tor_exit: true/false` |
| Tranco Domain Rank | `attack/tranco.py` | `tranco-list.eu` API | Domain ranking (domains only) |
| ThreatFox IOC | `attack/threatfox.py` | `abuse.ch` ThreatFox API | Malware tag, confidence level (domains only) |

### Mode 2 — Footprint (Email / Phone / Username)

| Module | File | Data Source | What it returns |
|---|---|---|---|
| Email Breach Check | `osint/xposedornot.py` | XposedOrNot API | Exposed breaches, password strength, risk score |
| Phone Validation | `osint/phone.py` | NumVerify API | Country, carrier, line type |
| Username Search | `osint/username.py` | Multithreaded HTTP scraping via Sagemode | List of social platforms where username was found |

> **Note:** `attack/whoisripe.py`, `attack/onyphe.py`, and `attack/tweetfeeds.py` exist in the codebase but are **not wired into `main.py`**. They are unused stubs. The orchestrator should not expect output from them.

---

## 2. Real API Endpoints

All routes are served under the prefix `/api/Recon-Analyzer` **(capital R and capital A — exact casing is required).**

| Method | Route | Purpose | Input body |
|---|---|---|---|
| `GET` | `/api/Recon-Analyzer/health` | Health check | None |
| `POST` | `/api/Recon-Analyzer/scan` | IP or domain threat intel | `{"query": "ip_or_domain"}` |
| `POST` | `/api/Recon-Analyzer/footprint` | Email / phone / username OSINT | `{"query": "email_or_phone_or_username"}` |

> **Critical correction from the generic docs:** The request body key is `"query"`, **not** `"target"`. The old docs assumed `{"target": "..."}` — this will return a `400` from the real service.

---

## 3. Exact Response Shapes

### `GET /api/Recon-Analyzer/health`

```json
{"status": "healthy"}
```

---

### `POST /api/Recon-Analyzer/scan` — IP input

```json
{
  "query": "8.8.8.8",
  "ipapi": {
    "ip_info": [
      {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "region": "VA",
        "regionName": "Virginia",
        "city": "Ashburn",
        "zip": "20149",
        "timezone": "America/New_York",
        "isp": "Google LLC",
        "org": "Google LLC",
        "as": "AS15169 Google LLC"
      }
    ],
    "dns_info": { "dns": { "ip": "...", "geo": "..." }, "edns": {...} }
  },
  "talos": { "blacklisted": false },
  "tor":   { "is_tor_exit": false }
}
```

### `POST /api/Recon-Analyzer/scan` — Domain input

Same shape as above plus two additional keys (only present for domains):

```json
{
  "query": "evil.example.com",
  "ipapi":    { ... },
  "talos":    { "blacklisted": false },
  "tor":      { "is_tor_exit": false },
  "tranco":   { "found": false },
  "threatfox": {
    "found": true,
    "id": "12345",
    "ioc": "evil.example.com",
    "threat_type": "botnet_cc",
    "malware": "Emotet",
    "confidence_level": 90,
    "reference": "https://...",
    "link": "https://threatfox.abuse.ch/ioc/12345"
  }
}
```

If domain is not in ThreatFox: `"threatfox": { "found": false }`

---

### `POST /api/Recon-Analyzer/footprint` — Email

```json
{
  "query": "user@example.com",
  "type": "email",
  "email_scan": {
    "exposed": true,
    "breach_count": 3,
    "breaches": [
      { "breach": "Adobe", "domain": "adobe.com", "xposed_data": "Emails, Passwords" }
    ],
    "password_strength": [ {"PasswordStrength": "StrongHash", "count": 2} ],
    "risk": { "risk_label": "High Risk", "risk_score": 8 }
  }
}
```

If email is clean: `"email_scan": { "exposed": false, "message": "Email not found in any breach database" }`

---

### `POST /api/Recon-Analyzer/footprint` — Phone

```json
{
  "query": "+14155552671",
  "type": "phone",
  "phone_scan": {
    "valid": true,
    "country_code": "US",
    "country_name": "United States",
    "location": "California",
    "carrier": "AT&T",
    "line_type": "mobile"
  }
}
```

---

### `POST /api/Recon-Analyzer/footprint` — Username

```json
{
  "query": "johndoe",
  "type": "username",
  "username_scan": [
    { "site": "GitHub", "url": "https://github.com/johndoe" },
    { "site": "Twitter", "url": "https://twitter.com/johndoe" }
  ]
}
```

---

### Error shapes

```json
{ "error": "No IP or domain provided." }           // 400 — missing query
{ "error": "Invalid IP or domain format." }        // 400 — bad format
{ "error": "Unable to resolve domain: bad.xyz" }   // 400 — DNS failure
```

---

## 4. Port Mapping for SecFlow

The `Recon-Analyzer` service's own `docker-compose.yml` already maps to port `5003` on the host:

```
Recon-Analyzer standalone: container port 5000 → host port 5003
SecFlow integrated:         container port 5000 → host port 5003  (same)
```

The Orchestrator always calls it via Docker service name on container port 5000:
```
http://recon-analyzer:5000/api/Recon-Analyzer/scan
```

> Set `RECON_ANALYZER_URL=http://recon-analyzer:5000/api/Recon-Analyzer/` in the orchestrator environment. The `5003` is only used for direct host access (e.g., Postman testing from outside Docker).

---

## 5. Dockerfile Considerations

The Recon Analyzer is a lightweight container compared to the Malware Analyzer:

```
Base image:  python:3.12-slim
System deps: build-essential only
Working dir: /app/src  (gunicorn imports main:app from here)
```

**Important — Dockerfile naming issue:** The file is named `DockerFile` (capital F), but the service's own `docker-compose.yml` references it as `dockerfile` (lowercase). On Linux filesystems this is case-sensitive and will cause a build failure.

**Fix:** When adding to SecFlow's `compose.yml`, reference the correct capitalized filename:
```yaml
build:
  context: ./Recon-Analyzer
  dockerfile: DockerFile      # capital F — matches the actual file
```

**No JVM, no heavy downloads** — build time is ~30–60 seconds. No special memory limits needed (default Docker limits are fine).

---

## 6. Environment Variables

### Required / Optional by the Recon Analyzer

| Variable | Used by | Required? | Notes |
|---|---|---|---|
| `NUMVERIFY_API_KEY` | `phone.py` — NumVerify phone validation | Optional | Without it, `/footprint` with phone returns `{"valid": false, "error": "API key not configured"}` |
| `THREATFOX_API_KEY` | `threatfox.py` — ThreatFox IOC lookup | Optional | Without it, the API is still called but at a lower rate limit |
| `ipAPI_KEY` | `ipapi.py` — ip-api.com geolocation | Optional | Free tier works without a key |

> Note: `onypheAPI_KEY` appears in `attack/onyphe.py` but that module is not wired into `main.py` — it can be ignored.

### How to pass them from SecFlow `compose.yml`

```yaml
recon-analyzer:
  env_file:
    - ./Recon-Analyzer/.env
```

The `.env` file already has real keys populated. In the root `backend/.env.example`:
```
NUMVERIFY_API_KEY=
THREATFOX_API_KEY=
ipAPI_KEY=
```

---

## 7. Which Endpoint the Orchestrator Should Call

The orchestrator's `_call_analyzer("recon", ...)` should call **`/scan`** for IP and domain inputs (the primary pipeline use case):

```python
requests.post(
    "http://recon-analyzer:5000/api/Recon-Analyzer/scan",
    json={"query": ip_or_domain},
    timeout=60
)
```

The `/footprint` endpoint is a secondary use case — the orchestrator could call it if a previous analyzer pass (e.g., malware) surfaces an email address in its findings. It is not part of the primary routing loop.

**Timeout:** 60 seconds is sufficient. The slowest operations are ThreatFox and Tranco (external API calls), but both have 10–15 second internal timeouts. Talos and Tor lookups are local file reads and are near-instant.

---

## 8. Writing `recon_adapter.py`

**File:** `backend/orchestrator/app/adapters/recon_adapter.py`

This adapter receives the raw `/scan` response and maps it to the SecFlow findings contract.

```python
# backend/orchestrator/app/adapters/recon_adapter.py
"""
Adapter: Recon-Analyzer → SecFlow contract

The orchestrator calls:
  POST http://recon-analyzer:5000/api/Recon-Analyzer/scan
  Body: {"query": "<ip_or_domain>"}

Response shape:
  {
    "query": str,
    "ipapi":     { "ip_info": [...], "dns_info": {...} },
    "talos":     { "blacklisted": bool },
    "tor":       { "is_tor_exit": bool },
    "tranco":    { "found": bool, "rank": int },        # domains only
    "threatfox": { "found": bool, ... }                 # domains only
  }
"""
import json

RISK_MAP = {"critical": 4.0, "high": 2.5, "medium": 1.0, "low": 0.3, "info": 0.0}


def _parse_ipapi(ipapi: dict) -> list[dict]:
    """Extract geolocation findings from ipapi response."""
    findings = []
    ip_info_list = ipapi.get("ip_info", [])
    if not ip_info_list:
        return findings

    info = ip_info_list[0] if isinstance(ip_info_list, list) else ip_info_list
    if info.get("status") != "success":
        return findings

    detail = (
        f"IP: {info.get('query', '?')} | "
        f"Location: {info.get('city', '?')}, {info.get('regionName', '?')}, {info.get('country', '?')} | "
        f"ISP: {info.get('isp', '?')} | "
        f"ASN: {info.get('as', '?')}"
    )
    findings.append({
        "type": "geolocation",
        "detail": detail,
        "severity": "info",
        "evidence": json.dumps(info),
    })
    return findings


def _parse_talos(talos: dict) -> list[dict]:
    """Extract Talos blocklist finding."""
    findings = []
    if talos.get("error"):
        findings.append({
            "type": "error",
            "detail": f"Talos check failed: {talos['error']}",
            "severity": "low",
            "evidence": "",
        })
        return findings

    if talos.get("blacklisted"):
        findings.append({
            "type": "threat_intel",
            "detail": "IP is listed in the Cisco Talos IP blocklist",
            "severity": "critical",
            "evidence": "Source: snort.org/downloads/ip-block-list",
        })
    return findings


def _parse_tor(tor: dict) -> list[dict]:
    """Extract Tor exit node finding."""
    findings = []
    if tor.get("is_tor_exit"):
        findings.append({
            "type": "threat_intel",
            "detail": "IP is a known Tor exit node",
            "severity": "high",
            "evidence": "Source: check.torproject.org/exit-addresses",
        })
    return findings


def _parse_tranco(tranco: dict) -> list[dict]:
    """Extract domain ranking finding."""
    findings = []
    if tranco.get("found"):
        rank = tranco.get("rank", 0)
        # Very high rank (low number) means well-known domain — lower suspicion
        severity = "info" if rank < 10000 else "low"
        findings.append({
            "type": "domain_intel",
            "detail": f"Domain ranked #{rank} in Tranco top list",
            "severity": severity,
            "evidence": f"Tranco rank: {rank}",
        })
    return findings


def _parse_threatfox(threatfox: dict) -> list[dict]:
    """Extract ThreatFox IOC finding."""
    findings = []
    if not threatfox.get("found"):
        return findings

    malware = threatfox.get("malware", "unknown")
    threat_type = threatfox.get("threat_type", "unknown")
    confidence = threatfox.get("confidence_level", "?")
    link = threatfox.get("link", "")

    findings.append({
        "type": "threat_intel",
        "detail": (
            f"ThreatFox IOC match: {malware} | "
            f"Type: {threat_type} | "
            f"Confidence: {confidence}%"
        ),
        "severity": "critical",
        "evidence": link or json.dumps(threatfox),
    })
    return findings


def adapt(raw: dict, pass_number: int, input_data: str) -> dict:
    """
    Transform the Recon-Analyzer /scan response into a SecFlow contract dict.

    Args:
        raw:         JSON response body from POST /api/Recon-Analyzer/scan
        pass_number: Current loop pass (1-indexed)
        input_data:  The IP or domain that was scanned

    Returns:
        SecFlow contract dict
    """
    # Handle error response from service
    if "error" in raw and len(raw) == 1:
        return {
            "analyzer": "recon",
            "pass": pass_number,
            "input": input_data,
            "findings": [{
                "type": "error",
                "detail": raw["error"],
                "severity": "low",
                "evidence": "",
            }],
            "risk_score": 0.0,
            "raw_output": json.dumps(raw),
        }

    findings = []
    findings.extend(_parse_ipapi(raw.get("ipapi", {})))
    findings.extend(_parse_talos(raw.get("talos", {})))
    findings.extend(_parse_tor(raw.get("tor", {})))
    findings.extend(_parse_tranco(raw.get("tranco", {})))
    findings.extend(_parse_threatfox(raw.get("threatfox", {})))

    risk_score = min(10.0, sum(RISK_MAP.get(f.get("severity", "info"), 0.0) for f in findings))

    # Build raw_output — the text Gemini reads when deciding next analyzer
    raw_parts = []
    if raw.get("ipapi"):
        ip_info = raw["ipapi"].get("ip_info", [{}])
        info = ip_info[0] if isinstance(ip_info, list) and ip_info else {}
        raw_parts.append(
            f"IP: {info.get('query', input_data)} | "
            f"Country: {info.get('country', '?')} | "
            f"ISP: {info.get('isp', '?')} | "
            f"ASN: {info.get('as', '?')}"
        )
    if raw.get("talos", {}).get("blacklisted"):
        raw_parts.append("ALERT: IP is on Cisco Talos blocklist")
    if raw.get("tor", {}).get("is_tor_exit"):
        raw_parts.append("ALERT: IP is a known Tor exit node")
    if raw.get("tranco", {}).get("found"):
        raw_parts.append(f"Domain Tranco rank: {raw['tranco']['rank']}")
    if raw.get("threatfox", {}).get("found"):
        tf = raw["threatfox"]
        raw_parts.append(
            f"ThreatFox: {tf.get('malware', '?')} ({tf.get('threat_type', '?')}) "
            f"confidence {tf.get('confidence_level', '?')}%"
        )

    return {
        "analyzer": "recon",
        "pass": pass_number,
        "input": input_data,
        "findings": findings,
        "risk_score": risk_score,
        "raw_output": "\n".join(raw_parts) if raw_parts else json.dumps(raw),
    }
```

---

### How `_call_analyzer` calls the Recon service in `orchestrator.py`

No special multi-request pattern needed (unlike the Malware Analyzer). A single `POST /scan` is sufficient:

```python
# In backend/orchestrator/app/orchestrator.py
# This is the existing generic path — recon works with it as-is:

elif tool == "recon":
    resp = requests.post(
        ANALYZER_URLS["recon"] + "scan",   # → http://recon-analyzer:5000/api/Recon-Analyzer/scan
        json={"query": input_data},
        timeout=60,
    )
    resp.raise_for_status()
    return recon_adapter.adapt(resp.json(), pass_number, input_data)
```

> Make sure `ANALYZER_URLS["recon"]` is set to `http://recon-analyzer:5000/api/Recon-Analyzer/` (with trailing slash) so the concatenated URL becomes `http://recon-analyzer:5000/api/Recon-Analyzer/scan`.

---

## 9. Updating `compose.yml`

Add the following service block to `backend/compose.yml`:

```yaml
  recon-analyzer:
    build:
      context: ./Recon-Analyzer
      dockerfile: DockerFile        # capital F — exact filename on disk
    container_name: recon-analyzer
    ports:
      - "5003:5000"                 # host 5003 → container 5000
    env_file:
      - ./Recon-Analyzer/.env
    environment:
      - PORT=5000
      - PYTHONUNBUFFERED=1
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/Recon-Analyzer/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    networks:
      - secflow-net
    restart: unless-stopped
```

> **Key difference from the service's own `docker-compose.yml`:** The original service-level network name differs from the shared platform network. Use `secflow-net` so the Orchestrator can reach Recon Analyzer by service name.

### Update `RECON_ANALYZER_URL` in the orchestrator service:

```yaml
  orchestrator:
    environment:
      - RECON_ANALYZER_URL=http://recon-analyzer:5000/api/Recon-Analyzer/
```

---

## 10. Classifier Rule for Recon

In `backend/orchestrator/app/classifier/rules.py`, the recon routing rules detect IPv4 addresses and domains. These match the same regexes used inside `main.py`:

```python
import re

RULES: list[tuple] = [
    # ... (image → steg, executable → malware, URL → web) ...

    # IPv4 addresses → Recon
    (lambda mime, magic, raw: bool(re.match(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        raw.strip()
    )), "recon"),

    # Domains → Recon (same regex as used in Recon-Analyzer/src/main.py)
    (lambda mime, magic, raw: bool(re.match(
        r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$',
        raw.strip()
    )), "recon"),
]
```

> Note: URLs (`https://example.com`) must be caught by the **web** rule **before** the domain rule, since a bare domain like `example.com` and the domain portion of a URL would both match the domain regex. The web rule must appear earlier in the `RULES` list.

---

## 11. Input Extraction Between Passes

When a previous analyzer surfaces an IP or domain in its findings, the orchestrator extracts it as input for the Recon Analyzer:

```python
# In backend/orchestrator/app/orchestrator.py — _extract_next_input()

if next_tool == "recon":
    raw = last_finding.get("raw_output", "")
    findings = last_finding.get("findings", [])

    # 1. Try to find an IP in findings evidence or raw_output
    import re
    ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', raw)
    if ips:
        # Skip private/loopback ranges
        public_ips = [
            ip for ip in ips
            if not ip.startswith(("192.168.", "10.", "172.", "127.", "0."))
        ]
        if public_ips:
            return public_ips[0]

    # 2. Try to find a domain
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', raw)
    # Filter out common noise (file extensions, internal names)
    noise = {".exe", ".dll", ".png", ".jpg", ".pdf", ".txt", ".bin"}
    for domain in domains:
        if not any(domain.endswith(ext) for ext in noise):
            return domain

    # 3. Fall back to the original input if it's already an IP/domain
    original = last_finding.get("input", "")
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', original) or \
       re.match(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', original):
        return original
```

---

## 12. Known Issues and Fixes

### Issue 1 — `dockerfile` case mismatch

**Problem:** The service's own `docker-compose.yml` has:
```yaml
build:
  context: .
  Dockerfile: dockerfile    # lowercase
```
But the actual file on disk is `DockerFile` (capital F). On Linux this fails with `failed to read dockerfile: open dockerfile: no such file or directory`.

**Fix:** In SecFlow's `compose.yml`, always use:
```yaml
dockerfile: DockerFile      # match exact filename on disk
```

---

### Issue 2 — `onyphe.py` has a `print()` at module level

**Problem:** `attack/onyphe.py` ends with `print(onphe("aegisclub.tech", "domain"))` at the top level. This runs on import and will crash the container if `onypheAPI_KEY` is not set (or if the Onyphe API is unreachable).

**Impact:** Since `onyphe.py` is **not imported by `main.py`**, this is currently harmless. Do not import it.

---

### Issue 3 — `whoisripe.py` has a `print()` at module level

**Problem:** `attack/whoisripe.py` ends with `print(whoisripe("google.com"))` at the top level. Same issue as above — runs on import.

**Impact:** Same as above — not imported by `main.py`, so no current risk.

---

### Issue 4 — `/footprint` with an unknown input type defaults to username search

**Problem:** The service's input type detection in `/footprint` uses email regex, then phone regex, and falls through to username for anything else. A mistyped email will silently be treated as a username search.

**Impact for the orchestrator:** Low — the orchestrator only calls `/scan` in the primary pipeline loop.

---

### Issue 5 — Tranco and ThreatFox only run for domains, not IPs

**Expected behavior:** When scanning a plain IP, the response will not contain `tranco` or `threatfox` keys. The adapter handles this correctly with `.get()` returning empty dicts.

---

## 13. Step-by-Step Integration Checklist

### Phase 1 — Verify the service starts standalone

```bash
cd backend/Recon-Analyzer
docker compose up --build
```

> **If you see:** `failed to read dockerfile: open dockerfile: no such file or directory`
> **Fix:** Edit `docker-compose.yml` → change `Dockerfile: dockerfile` to `dockerfile: DockerFile`

Expected:
```bash
curl http://localhost:5003/api/Recon-Analyzer/health
# {"status": "healthy"}
```

### Phase 2 — Test both endpoints individually

```bash
# Scan an IP
curl -X POST http://localhost:5003/api/Recon-Analyzer/scan \
  -H "Content-Type: application/json" \
  -d '{"query": "8.8.8.8"}'

# Scan a domain
curl -X POST http://localhost:5003/api/Recon-Analyzer/scan \
  -H "Content-Type: application/json" \
  -d '{"query": "google.com"}'

# Footprint — email
curl -X POST http://localhost:5003/api/Recon-Analyzer/footprint \
  -H "Content-Type: application/json" \
  -d '{"query": "test@example.com"}'
```

Verify the response contains `ipapi`, `talos`, and `tor` keys for an IP scan.
Verify `tranco` and `threatfox` appear when scanning a domain.

### Phase 3 — Write and unit-test the adapter

```python
# Run this as a test script:
import sys
sys.path.insert(0, "backend/orchestrator")
from app.adapters.recon_adapter import adapt

# Mock scan response for an IP
mock_ip_scan = {
    "query": "109.196.187.208",
    "ipapi": {
        "ip_info": [{
            "status": "success",
            "query": "109.196.187.208",
            "country": "Russia",
            "countryCode": "RU",
            "city": "Moscow",
            "isp": "LLC Baxet",
            "as": "AS57523 Chang Way Technologies Co. Limited"
        }],
        "dns_info": {}
    },
    "talos":    {"blacklisted": True},
    "tor":      {"is_tor_exit": False}
}

result = adapt(mock_ip_scan, pass_number=1, input_data="109.196.187.208")

assert result["analyzer"] == "recon"
assert result["pass"] == 1
assert isinstance(result["findings"], list)
assert 0.0 <= result["risk_score"] <= 10.0
assert "ALERT: IP is on Cisco Talos blocklist" in result["raw_output"]
print("Adapter test passed.")
print(f"Findings: {len(result['findings'])}, Risk: {result['risk_score']}")
```

### Phase 4 — Integrate into SecFlow compose

1. Add the `recon-analyzer` service block to `backend/compose.yml` (see Section 9)
2. Add `RECON_ANALYZER_URL=http://recon-analyzer:5000/api/Recon-Analyzer/` to the orchestrator service environment
3. Bring up all services:
   ```bash
   cd backend
   docker compose up --build
   ```

### Phase 5 — End-to-end pipeline test

```bash
# Direct IP → should route to recon on pass 1
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'

# Malware sample with C2 IP in decompiled output → malware → recon (pass 2)
curl -X POST "http://localhost:5000/api/smart-analyze?passes=3" \
  -F "file=@/path/to/sample.exe"
```

Expected checklist:
- [ ] `GET /api/Recon-Analyzer/health` returns `{"status": "healthy"}`
- [ ] `POST /scan` with `{"query": "8.8.8.8"}` returns `ipapi`, `talos`, `tor` keys
- [ ] `POST /scan` with a domain returns additionally `tranco` and `threatfox` keys
- [ ] `adapt()` produces a dict with `analyzer == "recon"`, `findings` list, `risk_score` in range
- [ ] Talos-listed IP produces a `critical` severity finding
- [ ] Orchestrator `_call_analyzer("recon", ...)` returns a valid SecFlow contract
- [ ] Findings are written to the Findings Store
- [ ] AI Decision Engine receives the `raw_output` and makes a routing decision
- [ ] Full pipeline run produces a report containing at least one recon pass

---

## Summary of Key Differences from Generic Docs

| Generic Doc Assumption | Actual Implementation |
|---|---|
| Single route `POST /api/recon-analyzer/` | Two routes: `/scan` and `/footprint` (under `/api/Recon-Analyzer/`) |
| Request key `{"target": "..."}` | Request key is `{"query": "..."}` |
| Container port 5003 | Container port is `5000`; host port `5003` is only the external mapping |
| WHOIS, DNS, port scanning, Shodan | No WHOIS/nmap/Shodan — uses ipapi, Talos, Tor, Tranco, ThreatFox |
| Single HTTP call sufficient | Single `POST /scan` call — no multi-request merge needed |
| Dockerfile is `Dockerfile` | File on disk is `DockerFile` (capital F) — must match exactly in compose |
| API prefix lowercase | API prefix is `/api/Recon-Analyzer` — capital R and capital A required |
