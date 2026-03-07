# Web-Analyzer API Documentation

Complete API reference for the Web-Analyzer service.

## Base URL

```
http://localhost:5000/api
```

## Authentication

Currently, no authentication is required. Rate limiting can be enabled via environment variables.

## Common Parameters

All endpoints accept the following query parameter:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| url | string | Yes | The target URL or domain to analyze |

## Response Format

All successful responses return JSON with HTTP status 200:

```json
{
  "key": "value",
  "data": { }
}
```

Error responses return JSON with appropriate HTTP status codes:

```json
{
  "error": "Error message description"
}
```

## Endpoints

### 1. Status Check
**GET** `/api/status`

Check if a website is up and measure response time.

**Example:**
```bash
curl "http://localhost:5000/api/status?url=example.com"
```

**Response:**
```json
{
  "isUp": true,
  "responseTime": 245.67,
  "responseCode": 200,
  "timestamp": 1705512345
}
```

---

### 2. DNS Records
**GET** `/api/dns`

Retrieve all DNS records for a domain.

**Example:**
```bash
curl "http://localhost:5000/api/dns?url=example.com"
```

**Response:**
```json
{
  "A": ["93.184.216.34"],
  "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
  "MX": [{"exchange": "mail.example.com", "preference": 10}],
  "TXT": ["v=spf1 include:_spf.example.com ~all"],
  "NS": ["ns1.example.com", "ns2.example.com"],
  "CNAME": [],
  "SOA": {...},
  "SRV": [],
  "PTR": []
}
```

---

### 3. SSL Certificate
**GET** `/api/ssl`

Get SSL/TLS certificate information.

**Example:**
```bash
curl "http://localhost:5000/api/ssl?url=example.com"
```

**Response:**
```json
{
  "subject": {"CN": "example.com"},
  "issuer": {"CN": "DigiCert TLS RSA SHA256 2020 CA1"},
  "notBefore": "Dec  1 00:00:00 2023 GMT",
  "notAfter": "Dec  1 23:59:59 2024 GMT",
  "subjectAltName": [["DNS", "example.com"], ["DNS", "www.example.com"]]
}
```

---

### 4. HTTP Headers
**GET** `/api/headers`

Fetch HTTP response headers.

**Example:**
```bash
curl "http://localhost:5000/api/headers?url=example.com"
```

**Response:**
```json
{
  "Server": "nginx",
  "Content-Type": "text/html; charset=UTF-8",
  "X-Frame-Options": "SAMEORIGIN",
  "Strict-Transport-Security": "max-age=31536000",
  ...
}
```

---

### 5. Technology Stack
**GET** `/api/tech-stack`

Detect technologies used on the website.

**Example:**
```bash
curl "http://localhost:5000/api/tech-stack?url=example.com"
```

**Response:**
```json
{
  "technologies": {
    "cms": [],
    "frameworks": ["React", "Bootstrap"],
    "languages": [],
    "servers": ["nginx"],
    "analytics": [],
    "cdn": []
  }
}
```

---

### 6. WHOIS Information
**GET** `/api/whois`

Get domain registration information.

**Example:**
```bash
curl "http://localhost:5000/api/whois?url=example.com"
```

**Response:**
```json
{
  "domain": "example.com",
  "whois_data": {
    "domain_name": "EXAMPLE.COM",
    "registrar": "Example Registrar, Inc.",
    "creation_date": "1995-08-14",
    "expiration_date": "2024-08-13",
    ...
  }
}
```

---

### 7. Robots.txt
**GET** `/api/robots-txt`

Parse robots.txt file.

**Example:**
```bash
curl "http://localhost:5000/api/robots-txt?url=example.com"
```

**Response:**
```json
{
  "robots": [
    {"type": "User-agent", "value": "*"},
    {"type": "Disallow", "value": "/admin"},
    {"type": "Allow", "value": "/public"}
  ]
}
```

---

### 8. Sitemap
**GET** `/api/sitemap`

Parse sitemap.xml file.

**Example:**
```bash
curl "http://localhost:5000/api/sitemap?url=example.com"
```

**Response:**
```json
{
  "entries": [
    {
      "loc": "https://example.com/page1",
      "lastmod": "2024-01-15",
      "changefreq": "daily",
      "priority": "0.8"
    }
  ],
  "count": 1
}
```

---

### 9. Cookies
**GET** `/api/cookies`

Analyze cookies set by the website.

**Example:**
```bash
curl "http://localhost:5000/api/cookies?url=example.com"
```

**Response:**
```json
{
  "headerCookies": "sessionid=abc123; Path=/; HttpOnly",
  "clientCookies": [
    {
      "name": "sessionid",
      "value": "abc123",
      "domain": "example.com",
      "path": "/",
      "secure": true,
      "httpOnly": true
    }
  ]
}
```

---

### 10. HSTS Check
**GET** `/api/hsts`

Check HTTP Strict Transport Security configuration.

**Example:**
```bash
curl "http://localhost:5000/api/hsts?url=example.com"
```

**Response:**
```json
{
  "message": "Site is compatible with the HSTS preload list!",
  "compatible": true,
  "hstsHeader": "max-age=31536000; includeSubDomains; preload",
  "maxAge": 31536000,
  "includesSubDomains": true,
  "preload": true
}
```

---

### 11. Security Headers
**GET** `/api/security-headers`

Check security-related HTTP headers.

**Example:**
```bash
curl "http://localhost:5000/api/security-headers?url=example.com"
```

**Response:**
```json
{
  "strictTransportPolicy": true,
  "xFrameOptions": true,
  "xContentTypeOptions": true,
  "xXSSProtection": false,
  "contentSecurityPolicy": true
}
```

---

### 12. Security.txt
**GET** `/api/security-txt`

Parse security.txt file.

**Example:**
```bash
curl "http://localhost:5000/api/security-txt?url=example.com"
```

**Response:**
```json
{
  "isPresent": true,
  "foundIn": "/.well-known/security.txt",
  "isPgpSigned": false,
  "fields": {
    "Contact": "security@example.com",
    "Expires": "2024-12-31T23:59:59.000Z"
  }
}
```

---

### 13. Redirects
**GET** `/api/redirects`

Trace URL redirect chain.

**Example:**
```bash
curl "http://localhost:5000/api/redirects?url=example.com"
```

**Response:**
```json
{
  "redirects": [
    "http://example.com",
    "https://example.com",
    "https://www.example.com"
  ]
}
```

---

### 14. Port Scan
**GET** `/api/ports`

Scan commonly used ports.

**Example:**
```bash
curl "http://localhost:5000/api/ports?url=example.com"
```

**Response:**
```json
{
  "host": "93.184.216.34",
  "openPorts": [80, 443],
  "closedPorts": [21, 22, 25, ...]
}
```

---

### 15. Get IP
**GET** `/api/get-ip`

Get IP address of domain.

**Example:**
```bash
curl "http://localhost:5000/api/get-ip?url=example.com"
```

**Response:**
```json
{
  "ip": "93.184.216.34",
  "family": 4,
  "address": "example.com"
}
```

---

### 16. Social Tags
**GET** `/api/social-tags`

Extract social media meta tags.

**Example:**
```bash
curl "http://localhost:5000/api/social-tags?url=example.com"
```

**Response:**
```json
{
  "title": "Example Domain",
  "description": "This domain is for use in examples",
  "ogTitle": "Example Domain",
  "ogImage": "https://example.com/og-image.png",
  "twitterCard": "summary_large_image"
}
```

---

### 17. TXT Records
**GET** `/api/txt-records`

Get DNS TXT records.

**Example:**
```bash
curl "http://localhost:5000/api/txt-records?url=example.com"
```

**Response:**
```json
{
  "v": "spf1 include:_spf.example.com ~all",
  "google-site-verification": "abc123..."
}
```

---

### 18. Linked Pages
**GET** `/api/linked-pages`

Extract internal and external links.

**Example:**
```bash
curl "http://localhost:5000/api/linked-pages?url=example.com"
```

**Response:**
```json
{
  "internal": ["https://example.com/about", "https://example.com/contact"],
  "external": ["https://iana.org"]
}
```

---

### 19. Trace Route
**GET** `/api/trace-route`

Trace network route to host.

**Example:**
```bash
curl "http://localhost:5000/api/trace-route?url=example.com"
```

**Response:**
```json
{
  "message": "Traceroute completed!",
  "result": [
    {"hop": 1, "info": "192.168.1.1  1.234 ms"},
    {"hop": 2, "info": "10.0.0.1  5.678 ms"}
  ]
}
```

---

### 20. Mail Configuration
**GET** `/api/mail-config`

Analyze email server configuration.

**Example:**
```bash
curl "http://localhost:5000/api/mail-config?url=example.com"
```

**Response:**
```json
{
  "mxRecords": [
    {"exchange": "mail.example.com", "preference": 10}
  ],
  "txtRecords": ["v=spf1 include:_spf.example.com ~all"],
  "mailServices": [
    {"provider": "Google Workspace", "value": "verification-code"}
  ]
}
```

---

### 21. DNSSEC
**GET** `/api/dnssec`

Check DNSSEC configuration.

**Example:**
```bash
curl "http://localhost:5000/api/dnssec?url=example.com"
```

**Response:**
```json
{
  "DNSKEY": {"isFound": true, "answer": [...]},
  "DS": {"isFound": true, "answer": [...]},
  "RRSIG": {"isFound": false, "answer": null}
}
```

---

### 22. Firewall Detection
**GET** `/api/firewall`

Detect Web Application Firewall.

**Example:**
```bash
curl "http://localhost:5000/api/firewall?url=example.com"
```

**Response:**
```json
{
  "hasWaf": true,
  "waf": "Cloudflare"
}
```

---

### 23. DNS Server
**GET** `/api/dns-server`

Check DNS server configuration.

**Example:**
```bash
curl "http://localhost:5000/api/dns-server?url=example.com"
```

**Response:**
```json
{
  "domain": "example.com",
  "dns": [
    {
      "address": "93.184.216.34",
      "hostname": ["example.com"],
      "dohDirectSupports": false
    }
  ]
}
```

---

### 24. TLS Configuration
**GET** `/api/tls`

Check TLS configuration via Mozilla Observatory.

**Example:**
```bash
curl "http://localhost:5000/api/tls?url=example.com"
```

**Response:**
```json
{
  "scan_id": 12345,
  "grade": "A",
  "score": 95,
  ...
}
```

---

### 25. Batch Analysis
**GET/POST** `/api/batch`

Run all available checks at once.

**Example:**
```bash
curl "http://localhost:5000/api/batch?url=example.com"
```

**Response:**
```json
{
  "status": {...},
  "dns": {...},
  "ssl": {...},
  ...
}
```

## Rate Limiting

When enabled, rate limits apply per IP address:
- 100 requests per 10 minutes
- 250 requests per hour
- 500 requests per 12 hours

Rate limit responses return HTTP 429:
```json
{
  "error": "You've been rate-limited, please try again in 10 minutes..."
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 408 | Request Timeout |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

## Best Practices

1. Always URL-encode the `url` parameter
2. Handle timeout errors gracefully
3. Use batch endpoint for comprehensive analysis
4. Respect rate limits
5. Cache results when possible

## Examples

### Python
```python
import requests

response = requests.get('http://localhost:5000/api/status', params={'url': 'example.com'})
data = response.json()
print(data)
```

### JavaScript
```javascript
fetch('http://localhost:5000/api/status?url=example.com')
  .then(response => response.json())
  .then(data => console.log(data));
```

### cURL
```bash
curl -X GET "http://localhost:5000/api/batch?url=example.com" \
  -H "Accept: application/json"
```

  ---

  ## Additional Endpoints (Require API Keys)

  ### 26. Archives (Wayback Machine)
  **GET** `/api/archives`

  Get historical snapshots from Internet Archive's Wayback Machine.

  **Example:**
  ```bash
  curl "http://localhost:5000/api/archives?url=example.com"
  ```

  **Response:**
  ```json
  {
    "firstScan": "2005-01-15T10:30:00",
    "lastScan": "2024-01-17T14:20:00",
    "totalScans": 15234,
    "changeCount": 1203,
    "averagePageSize": 45678,
    "scanFrequency": {
      "daysBetweenScans": 4.5,
      "daysBetweenChanges": 57.2,
      "scansPerDay": 0.22,
      "changesPerDay": 0.017
    },
    "scans": []
  }
  ```

  ### 27. Carbon Footprint
  **GET** `/api/carbon`

  Calculate website carbon emissions using Website Carbon API.

  **Example:**
  ```bash
  curl "http://localhost:5000/api/carbon?url=example.com"
  ```

  **Response:**
  ```json
  {
    "statistics": {
      "adjustedBytes": 123456,
      "energy": 0.00012,
      "co2": {
        "renewable": 0.000045,
        "grid": 0.000078
      }
    },
    "cleanerThan": 67.5,
    "scanUrl": "https://example.com"
  }
  ```

  ### 28. Security Threats
  **GET** `/api/threats`

  Check URL against multiple threat databases.

  **Requires:** `GOOGLE_CLOUD_API_KEY`, `CLOUDMERSIVE_API_KEY`

  **Example:**
  ```bash
  curl "http://localhost:5000/api/threats?url=example.com"
  ```

  **Response:**
  ```json
  {
    "urlHaus": {"query_status": "ok", "threat": "not_found"},
    "phishTank": {"in_database": "false"},
    "cloudmersive": {"CleanResult": true, "ThreatScore": 0},
    "safeBrowsing": {"unsafe": false}
  }
  ```

  ### 29. Quality (PageSpeed Insights)
  **GET** `/api/quality`

  Get Google PageSpeed Insights quality metrics.

  **Requires:** `GOOGLE_CLOUD_API_KEY`

  **Example:**
  ```bash
  curl "http://localhost:5000/api/quality?url=example.com"
  ```

  **Response:**
  ```json
  {
    "lighthouseResult": {
      "categories": {
        "performance": {"score": 0.85},
        "accessibility": {"score": 0.92},
        "best-practices": {"score": 0.88},
        "seo": {"score": 0.95},
        "pwa": {"score": 0.45}
      }
    }
  }
  ```

  ### 30. Domain Ranking (Tranco)
  **GET** `/api/rank`

  Get domain ranking from Tranco research list.

  **Optional:** `TRANCO_USERNAME`, `TRANCO_API_KEY`

  **Example:**
  ```bash
  curl "http://localhost:5000/api/rank?url=example.com"
  ```

  **Response:**
  ```json
  {
    "ranks": [
      {"rank": 12345, "date": "2024-01-15"}
    ]
  }
  ```

  ### 31. Legacy Ranking (Umbrella/Alexa)
  **GET** `/api/legacy-rank`

  Get domain ranking from Cisco Umbrella top 1M list.

  **Example:**
  ```bash
  curl "http://localhost:5000/api/legacy-rank?url=example.com"
  ```

  **Response:**
  ```json
  {
    "domain": "example.com",
    "rank": 12345,
    "isFound": true
  }
  ```

  ### 32. Website Features (BuiltWith)
  **GET** `/api/features`

  Get detailed website features and technologies via BuiltWith API.

  **Requires:** `BUILT_WITH_API_KEY`

  **Example:**
  ```bash
  curl "http://localhost:5000/api/features?url=example.com"
  ```

  **Response:**
  ```json
  {
    "Results": [
      {
        "Result": {
          "Paths": [
            {
              "Technologies": [
                {
                  "Tag": "Cloudflare",
                  "Categories": ["CDN"]
                }
              ]
            }
          ]
        }
      }
    ]
  }
  ```

  ### 33. DNS Blocklists
  **GET** `/api/block-lists`

  Check if domain is blocked by various DNS providers.

  **Example:**
  ```bash
  curl "http://localhost:5000/api/block-lists?url=example.com"
  ```

  **Response:**
  ```json
  {
    "blocklists": [
      {
        "server": "AdGuard",
        "serverIp": "176.103.130.130",
        "isBlocked": false
      },
      {
        "server": "CloudFlare Family",
        "serverIp": "1.1.1.3",
        "isBlocked": false
      }
    ]
  }
  ```

  ### 34. Screenshot
  **GET** `/api/screenshot`

  Capture website screenshot using Selenium.

  **Requires:** Chrome/Chromium installed (`CHROME_PATH`, `CHROMEDRIVER_PATH`)

  **Example:**
  ```bash
  curl "http://localhost:5000/api/screenshot?url=example.com"
  ```

  **Response:**
  ```json
  {
    "image": "iVBORw0KGgoAAAANSUhEUgAA... (base64 encoded PNG)"
  }
  ```

  ---

  ## API Key Configuration

  To use endpoints requiring external APIs, configure these environment variables in your `.env` file:

  ```bash
  # Google Cloud (quality, threats)
  GOOGLE_CLOUD_API_KEY=your_key_here

  # Cloudmersive (threats)
  CLOUDMERSIVE_API_KEY=your_key_here

  # BuiltWith (features)
  BUILT_WITH_API_KEY=your_key_here

  # Tranco (rank) - Optional
  TRANCO_USERNAME=your_username
  TRANCO_API_KEY=your_key_here

  # Chrome for screenshots
  CHROME_PATH=/usr/bin/chromium
  CHROMEDRIVER_PATH=/usr/bin/chromedriver
  ```

  ## Obtaining API Keys

  - **Google Cloud API Key**: https://console.cloud.google.com/ (Enable PageSpeed Insights API and Safe Browsing API)
  - **Cloudmersive**: https://cloudmersive.com/ (Free tier available)
  - **BuiltWith**: https://api.builtwith.com/ (Free tier available)
  - **Tranco**: https://tranco-list.eu/ (Registration optional, auth not required)

  ## Notes

  - Archives, Carbon, and Block-lists endpoints do NOT require API keys
  - Legacy-rank endpoint downloads a 20MB+ CSV file on first use (cached in /tmp)
  - Screenshot endpoint may require additional setup (Chrome/Chromium + ChromeDriver)
  - Most API endpoints have rate limits - check provider documentation
