# AGENT.md — Web-Analyzer Service

Context file for AI coding assistants (GitHub Copilot, etc.) working inside `backend/Web-Analyzer/`.

---

## What This Service Is

A **Flask-based web URL analysis microservice** (Python 3.11). It exposes 28 individual GET endpoints, each mapping to one specialized analysis task (DNS lookup, port scan, security headers, TLS check, WAF detection, etc.). It is one of five analyzer services in the SecFlow pipeline.

**In SecFlow:** This service runs as Docker container `web-analyzer` on port **5005** (SecFlow's `compose.yml`), reachable internally as `http://web-analyzer:5005`.

---

## Directory Structure

```
Web-Analyzer/
├── app/
│   ├── __init__.py              ← Flask app factory, CORS, rate limiting, blueprint registration
│   ├── routes/
│   │   └── api_routes.py        ← All 28 GET endpoints, Blueprint prefix: /api/web-analyzer
│   ├── services/                ← 28 self-contained service modules (one per endpoint)
│   │   ├── status_service.py
│   │   ├── dns_service.py
│   │   ├── ssl_service.py
│   │   ├── headers_service.py
│   │   ├── tech_stack_service.py
│   │   ├── whois_service.py
│   │   ├── robots_txt_service.py
│   │   ├── sitemap_service.py
│   │   ├── cookies_service.py
│   │   ├── hsts_service.py
│   │   ├── security_headers_service.py
│   │   ├── security_txt_service.py
│   │   ├── redirects_service.py
│   │   ├── ports_service.py
│   │   ├── get_ip_service.py
│   │   ├── social_tags_service.py
│   │   ├── txt_records_service.py
│   │   ├── linked_pages_service.py
│   │   ├── trace_route_service.py
│   │   ├── mail_config_service.py
│   │   ├── dnssec_service.py
│   │   ├── firewall_service.py
│   │   ├── dns_server_service.py
│   │   ├── tls_service.py
│   │   ├── archives_service.py
│   │   ├── carbon_service.py
│   │   ├── rank_service.py
│   │   ├── features_service.py
│   │   ├── block_lists_service.py
│   │   └── screenshot_service.py
│   └── utils/
│       └── middleware.py        ← normalize_url(), api_handler decorator, error handling
├── run.py                       ← Entry point: python run.py → http://localhost:5000
├── Dockerfile                   ← python:3.11-slim, installs dnsutils + traceroute system tools
├── docker-compose.yml           ← Standalone compose (maps 5001:5000)
├── requirements.txt
└── .env.example
```

---

## How to Run

```bash
# Standalone
cp .env.example .env
pip install -r requirements.txt
python run.py
# → http://localhost:5000/api/web-analyzer

# Docker (standalone)
docker compose up
# → http://localhost:5001/api/web-analyzer

# In SecFlow (via root compose.yml)
# → http://web-analyzer:5005/api/web-analyzer  (internal network)
# → http://localhost:5005/api/web-analyzer      (host-mapped)
```

---

## ⚠️ CRITICAL: Request Interface (Read Before Writing Adapter)

**All 28 endpoints are GET-only with a `?url=` query parameter.**

```
GET /api/web-analyzer/<endpoint>?url=<target-url>
```

**There is NO** `POST /api/web-analyzer/` combined-analysis endpoint.

This conflicts with how `AGENTS.md` / `migration.md` describe calling this service:
```python
# What the SecFlow spec says (WRONG for this service as-is):
requests.post("http://web-analyzer:5005/api/web-analyzer/", json={"url": url})

# What the service actually accepts:
requests.get("http://web-analyzer:5005/api/web-analyzer/security-headers", params={"url": url})
```

### Resolution Options (choose one when writing `web_adapter.py`):
1. **Add a `POST /api/web-analyzer/` combined route** to `app/routes/api_routes.py` that calls the most security-relevant sub-services and returns an aggregated response. ← **Recommended for SecFlow integration.**
2. Have the orchestrator's `web_adapter.py` call multiple GET endpoints directly and merge results.

---

## All 28 Endpoints

| Route | Service function | What it returns |
|---|---|---|
| `GET /api/web-analyzer/status` | `check_status(url)` | `{isUp, responseTime, responseCode}` |
| `GET /api/web-analyzer/dns` | `get_dns_records(url)` | `{A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR}` |
| `GET /api/web-analyzer/ssl` | `get_ssl_certificate(url)` | `{subject, issuer, version, notBefore, notAfter, subjectAltName}` |
| `GET /api/web-analyzer/headers` | `get_headers(url)` | Raw HTTP response headers dict |
| `GET /api/web-analyzer/tech-stack` | `detect_tech_stack(url)` | `{technologies: {cms, frameworks, languages, servers, analytics, cdn}}` |
| `GET /api/web-analyzer/whois` | `get_whois_data(url)` | `{domain, whois_data, source}` |
| `GET /api/web-analyzer/robots-txt` | `get_robots_txt(url)` | `{robots, url}` or `{skipped}` |
| `GET /api/web-analyzer/sitemap` | `get_sitemap(url)` | `{entries, count, url}` or `{skipped}` |
| `GET /api/web-analyzer/hsts` | `get_hsts_policy(url)` | `{present, policy, rawHeader}` |
| `GET /api/web-analyzer/security-headers` | `check_security_headers(url)` | `{present, missing, total_present, total_missing, score}` |
| `GET /api/web-analyzer/security-txt` | `get_security_txt(url)` | `{found, fields, url, content}` |
| `GET /api/web-analyzer/cookies` | `get_cookies(url)` | `{headerCookies, clientCookies}` or `{skipped}` |
| `GET /api/web-analyzer/redirects` | `get_redirects(url)` | `{redirects: [url1, url2, ...]}` |
| `GET /api/web-analyzer/ports` | `scan_ports(url)` | `{open: [...], closed: [...]}` — scans 34 common ports |
| `GET /api/web-analyzer/get-ip` | `get_ip(url)` | `{ip, family (4 or 6), address}` |
| `GET /api/web-analyzer/social-tags` | `get_social_tags(url)` | `{title, description, ogTitle, ogImage, twitterCard, ...}` |
| `GET /api/web-analyzer/txt-records` | `get_txt_records(url)` | Key-value dict of TXT records |
| `GET /api/web-analyzer/linked-pages` | `get_linked_pages(url)` | `{internal: [...], external: [...]}` |
| `GET /api/web-analyzer/trace-route` | `trace_route(url)` | Traceroute hops (native) or DNS fallback |
| `GET /api/web-analyzer/mail-config` | `get_mail_config(url)` | `{mx_records, spf, dkim, dmarc, mail_services}` |
| `GET /api/web-analyzer/dnssec` | `check_dnssec(url)` | `{DNSKEY, DS, RRSIG}` (via Google DoH API) |
| `GET /api/web-analyzer/firewall` | `detect_firewall(url)` | `{hasWaf, waf}` — detects 17+ WAF signatures |
| `GET /api/web-analyzer/dns-server` | `check_dns_server(url)` | `{address, hostname, dohDirectSupports}` |
| `GET /api/web-analyzer/tls` | `check_tls(url)` | `{tlsVersion, cipher, validCertificate, certificateIssuer}` |
| `GET /api/web-analyzer/archives` | `get_archives(url)` | Wayback Machine snapshot history |
| `GET /api/web-analyzer/carbon` | `get_carbon_footprint(url)` | Carbon/energy stats via websitecarbon.com API |
| `GET /api/web-analyzer/rank` | `get_rank(url)` | Tranco list ranking (skipped if not in top 100M) |
| `GET /api/web-analyzer/features` | `get_features(url)` | BuiltWith API tech detection (requires `BUILT_WITH_API_KEY`) |
| `GET /api/web-analyzer/block-lists` | `is_blocked(url)` | DNS blocklist check against 17 DNS providers |
| `GET /api/web-analyzer/screenshot` | `get_screenshot(url)` | Base64 screenshot via Selenium/Chrome |

---

## Key Implementation Details

### App Bootstrap (`app/__init__.py`)
- `Flask` app with `CORS(app, resources={r"/*": ...})` — all origins allowed
- Rate limiting: in-memory, disabled by default (`API_ENABLE_RATE_LIMIT=false`). 3 windows: 100/10min, 250/1hr, 500/12hr
- Blueprint registered: `app.register_blueprint(api_routes.bp)` — prefix `/api/web-analyzer`
- `DISABLE_EVERYTHING` env var can emergency-disable all routes

### middleware.py
- `normalize_url(url)` — prepends `https://` if no scheme present
- `api_handler` decorator — wraps every route handler: catches exceptions, returns `jsonify`, maps timeout errors to 408
- `timeout_handler` decorator — available but not applied globally

### Decorators applied to every route handler:
```python
@bp.route('/endpoint', methods=['GET'])
@check_rate_limit    # from app/__init__.py
@api_handler         # from app/utils/middleware.py
def handler():
    url = get_url_param()  # reads ?url= query param, normalizes
    return some_service.function(url)
```

### `get_url_param()` in routes
Reads `request.args.get('url')` and raises `ValueError` if missing.

### Port scanning
Uses `concurrent.futures.ThreadPoolExecutor(max_workers=10)` scanning 34 common ports (20-995, 3000-8888).

### Security headers checked
`X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security`, `Expect-CT`

### WAF detection
Detects 17 WAFs including Cloudflare, AWS WAF, Akamai, Sucuri, F5 BIG-IP, Cloudflare, ModSecurity, Wordfence, etc.

### Services using external APIs (require keys)
| Service | Env var | Required? |
|---|---|---|
| `features_service.py` | `BUILT_WITH_API_KEY` | Required — raises exception if missing |
| `rank_service.py` | `TRANCO_USERNAME` + `TRANCO_API_KEY` | Optional (unauthenticated access works) |
| `carbon_service.py` | none | Uses `api.websitecarbon.com` — no key needed |
| `dnssec_service.py` | none | Uses `dns.google` DoH API — no key needed |

### Services requiring system tools (in Dockerfile)
- `trace_route_service.py` — uses `traceroute` (Linux) / `tracert` (Windows) system command; falls back to DNS info if unavailable
- `screenshot_service.py` — requires Chromium + ChromeDriver (`CHROME_PATH`, `CHROMEDRIVER_PATH` env vars)

### `skipped` response pattern
Several services return `{"skipped": "reason"}` instead of erroring when data is simply absent (e.g., no robots.txt, no cookies, no Wayback snapshots). The adapter must handle this gracefully.

---

## Environment Variables

```bash
FLASK_ENV=development         # or production
PORT=5000                     # port to bind
API_TIMEOUT_LIMIT=20000       # ms — configures error message, not an actual timeout
API_CORS_ORIGIN=*
API_ENABLE_RATE_LIMIT=false   # set to "true" to enable in-memory rate limiting

# Optional external API keys
BUILT_WITH_API_KEY=           # required for /features endpoint
TRANCO_USERNAME=              # optional for /rank endpoint
TRANCO_API_KEY=               # optional for /rank endpoint

# Screenshot service
CHROME_PATH=/usr/bin/chromium
CHROMEDRIVER_PATH=/usr/bin/chromedriver
```

---

## Python Dependencies

```
Flask, Flask-CORS, python-dotenv
requests, urllib3, certifi, chardet, idna
dnspython
cryptography, pyOpenSSL
lxml, beautifulsoup4
pyppeteer
whois
validators
Werkzeug
selenium, webdriver-manager
```

---

## SecFlow Integration Notes

### What the orchestrator needs to send to this service:
Since there is no combined `POST /api/web-analyzer/` endpoint, the SecFlow integration requires **one of the following**:

**Option A (Recommended) — Add a combined POST endpoint to this service:**
```python
# Add to app/routes/api_routes.py
@bp.route('/', methods=['POST'])
def combined_analyze():
    data = request.get_json()
    url = normalize_url(data.get('url', ''))
    # Call the most security-relevant sub-services:
    # security_headers, tls, headers, firewall, cookies, redirects, ports, tech_stack, dns
    # Aggregate and return combined result
```

**Option B — Have the adapter call specific GET endpoints:**
```python
# In orchestrator/app/adapters/web_adapter.py
import requests
BASE = "http://web-analyzer:5005/api/web-analyzer"

def call_service(endpoint, url):
    try:
        r = requests.get(f"{BASE}/{endpoint}", params={"url": url}, timeout=20)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}

raw = {
    "security_headers": call_service("security-headers", url),
    "tls": call_service("tls", url),
    "headers": call_service("headers", url),
    "firewall": call_service("firewall", url),
    "ports": call_service("ports", url),
    "tech_stack": call_service("tech-stack", url),
    "cookies": call_service("cookies", url),
    "redirects": call_service("redirects", url),
}
```

### SecFlow contract the adapter must produce:
```python
{
    "analyzer": "web",
    "pass": int,
    "input": str,           # the URL
    "findings": list[dict], # each: {type, detail, severity, evidence}
    "risk_score": float,    # 0.0–10.0
    "raw_output": str       # JSON-serialized combined raw response
}
```

### Finding types to map from this service:
| Source | Finding type | Severity |
|---|---|---|
| missing security header | `missing_header` | `medium` |
| TLS deprecated version | `tls_issue` | `high` |
| tls ok | `tls_issue` | `info` |
| WAF detected | `tech_fingerprint` | `info` |
| no WAF detected | `tech_fingerprint` | `low` |
| open port (sensitive: 22, 23, 3389, etc.) | `open_port` | `high` |
| open port (normal: 80, 443) | `open_port` | `info` |
| tech stack (server/framework) | `tech_fingerprint` | `info` |
| insecure cookie (no Secure/HttpOnly) | `cookie` | `medium` |
| redirect chain | `redirect` | `info` |
| SSL cert info | `ssl_cert` | `info` |

---

## What NOT to Do

- Do **not** modify this service's code to match the SecFlow contract — write/update `orchestrator/app/adapters/web_adapter.py` instead.
- Do **not** assume a `POST /api/web-analyzer/` route exists — it doesn't (unless you add it).
- Do **not** import service modules directly into the orchestrator — always call via HTTP.
- Do **not** enable `API_ENABLE_RATE_LIMIT=true` in the SecFlow Docker environment — the orchestrator will hit rate limits calling this service multiple times per pipeline run.
- Do **not** include the screenshot, carbon, rank, or features endpoints in the security-focused adapter — they add latency and provide no security-relevant signal for the pipeline.
