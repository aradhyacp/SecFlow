# Web-Analyzer - Python Flask Backend

A comprehensive web URL analyzer built with Flask, designed to migrate the functionality of the web-check Node.js application into a Python backend.

## Features

Web-Analyzer provides multiple endpoints to analyze websites:

- **Cookies** - Extract cookies from website
- **HSTS** - Check HSTS policy
- **Security Headers** - Analyze security headers
- **Security.txt** - Parse security.txt file
- **Redirects** - Trace redirect chains
- **Ports** - Scan common open ports
- **Get IP** - Resolve website IP addresses
- **Social Tags** - Extract OpenGraph and Twitter Card meta tags
- **TXT Records** - Parse TXT DNS records
- **Linked Pages** - Extract internal and external links
- **Trace Route** - Network route tracing
- **Mail Config** - Email configuration analysis (MX, SPF, DKIM, DMARC)
- **DNSSEC** - Check DNSSEC validation
- **Firewall Detection** - Detect WAF and firewall presence
- **DNS Server** - Analyze DNS server configuration
- **TLS** - Check TLS configuration
- **Archives** - Wayback Machine historical snapshots
- **Carbon Footprint** - Website carbon emissions analysis
- **Security Threats** - Check against threat databases
- **Quality Metrics** - Google PageSpeed Insights scores
- **Domain Ranking** - Tranco and Umbrella rankings
- **Website Features** - BuiltWith technology detection
- **DNS Blocklists** - Check if domain is blocked by DNS providers
- **Screenshot** - Capture website screenshots

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup

1. Clone the repository
```bash
cd /home/sunaykulkarni/IntelX/backend/Web-Analyzer
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Configure environment variables
```bash
cp .env.example .env
# Edit .env as needed
```

4. Run the application
```bash
python run.py
```

The API will be available at `http://localhost:5000/api`

## API Endpoints

### Base URL
```
http://localhost:5000/api
```

### Available Endpoints

All endpoints require a `url` query parameter.

#### 1. Status Check
```
GET /api/status?url=example.com
```

Check if a website is up and get response metrics.

**Response:**
```json
{
  "isUp": true,
  "responseTime": 145.23,
  "responseCode": 200,
  "dnsLookupTime": 23.45,
  "timestamp": 1234567890
}
```

#### 2. DNS Records
```
GET /api/dns?url=example.com
```

Get all DNS records for a domain.

**Response:**
```json
{
  "A": ["93.184.216.34"],
  "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
  "MX": [{"exchange": "mail.example.com.", "preference": 10}],
  "TXT": ["v=spf1 include:example.com ~all"],
  "NS": ["ns1.example.com.", "ns2.example.com."],
  "CNAME": [],
  "SOA": [],
  "SRV": [],
  "PTR": []
}
```

#### 3. SSL Certificate
```
GET /api/ssl?url=example.com
```

Get SSL certificate information.

**Response:**
```json
{
  "subject": {"commonName": "example.com"},
  "issuer": {"commonName": "Certificate Authority"},
  "version": 3,
  "serialNumber": "0x123456",
  "notBefore": "Jan 1 00:00:00 2023 GMT",
  "notAfter": "Jan 1 00:00:00 2024 GMT",
  "subjectAltName": [["DNS", "example.com"], ["DNS", "*.example.com"]],
  "keyUsage": "Digital Signature, Key Encipherment"
}
```

#### 4. HTTP Headers
```
GET /api/headers?url=example.com
```

Get HTTP response headers.

**Response:**
```json
{
  "Content-Type": "text/html",
  "Server": "Apache/2.4.41",
  "Content-Length": "1234",
  "Cache-Control": "public, max-age=3600"
}
```

#### 5. Tech Stack Detection
```
GET /api/tech-stack?url=example.com
```

Detect technologies used on the website.

**Response:**
```json
{
  "technologies": {
    "cms": ["WordPress"],
    "frameworks": ["Bootstrap", "jQuery"],
    "languages": ["PHP"],
    "servers": ["Apache/2.4.41"],
    "analytics": [],
    "cdn": []
  },
  "url": "https://example.com",
  "status": "success"
}
```

#### 6. WHOIS Data
```
GET /api/whois?url=example.com
```

Get WHOIS information for a domain.

**Response:**
```json
{
  "domain": "example.com",
  "whois_data": {
    "registrar": "Example Registrar, Inc.",
    "registrant_name": "John Doe",
    "creation_date": "1995-08-14",
    "expiry_date": "2024-08-14"
  },
  "source": "whois.internic.net"
}
```

#### 7. Robots.txt
```
GET /api/robots-txt?url=example.com
```

Get robots.txt rules.

**Response:**
```json
{
  "robots": [
    {"type": "User-agent", "value": "*"},
    {"type": "Disallow", "value": "/admin"},
    {"type": "Allow", "value": "/public"}
  ],
  "url": "https://example.com/robots.txt"
}
```

#### 8. Sitemap
```
GET /api/sitemap?url=example.com
```

Get sitemap.xml entries.

**Response:**
```json
{
  "entries": [
    {
      "loc": "https://example.com/page1",
      "lastmod": "2024-01-15",
      "changefreq": "weekly",
      "priority": "0.8"
    }
  ],
  "count": 1,
  "url": "https://example.com/sitemap.xml"
}
```

#### 9. Batch Analysis
```
GET /api/batch?url=example.com
POST /api/batch
Content-Type: application/json

{"url": "example.com"}
```

Run all checks at once.

**Response:**
```json
{
  "status": {...},
  "dns": {...},
  "ssl": {...},
  "headers": {...},
  "tech-stack": {...},
  "whois": {...},
  "robots-txt": {...},
  "sitemap": {...}
}
```

## Configuration

Edit the `.env` file to configure:

- `FLASK_ENV` - Set to `development` or `production`
- `PORT` - Server port (default: 5000)
- `API_TIMEOUT_LIMIT` - Request timeout in milliseconds (default: 20000)
- `API_CORS_ORIGIN` - CORS allowed origins (default: *)
- `API_ENABLE_RATE_LIMIT` - Enable rate limiting (default: false)

## Rate Limiting

When enabled, rate limiting applies these limits:

- 100 requests per 10 minutes
- 250 requests per 1 hour
- 500 requests per 12 hours

Enable in `.env`:
```
API_ENABLE_RATE_LIMIT=true
```

## Docker Support

Build and run with Docker:

```bash
# Build image
docker build -t web-analyzer .

# Run container
docker run -p 5000:5000 web-analyzer
```

## Project Structure

```
Web-Analyzer/
├── app/
│   ├── __init__.py              # Flask app initialization
│   ├── routes/
│   │   ├── __init__.py
│   │   └── api_routes.py        # API endpoint definitions
│   ├── services/
│   │   ├── __init__.py
│   │   ├── status_service.py    # Website status check
│   │   ├── dns_service.py       # DNS record fetching
│   │   ├── ssl_service.py       # SSL certificate info
│   │   ├── headers_service.py   # HTTP headers
│   │   ├── tech_stack_service.py # Tech detection
│   │   ├── whois_service.py     # WHOIS lookup
│   │   ├── robots_txt_service.py # Robots.txt parsing
│   │   └── sitemap_service.py   # Sitemap parsing
│   └── utils/
│       ├── __init__.py
│       └── middleware.py         # Middleware & utilities
├── run.py                        # Application entry point
├── requirements.txt              # Python dependencies
├── .env                         # Environment configuration
├── .env.example                 # Example configuration
└── README.md                    # This file
```

## Dependencies

- **Flask** - Web framework
- **Flask-CORS** - CORS support
- **requests** - HTTP client
- **dnspython** - DNS queries
- **cryptography** - SSL/TLS support
- **beautifulsoup4** - HTML parsing
- **lxml** - XML parsing
- **python-dotenv** - Environment variable loading

## Error Handling

The API returns appropriate HTTP status codes:

- `200` - Successful request
- `400` - Bad request (missing URL parameter)
- `408` - Request timeout
- `429` - Rate limited
- `500` - Internal server error
- `503` - Service disabled

Error responses include detailed messages:

```json
{
  "error": "Unable to extract hostname from URL"
}
```

## Performance Considerations

- Default timeout: 20 seconds per request
- Rate limiting to prevent abuse
- Asynchronous error handling
- Connection pooling for HTTP requests

## Security

- CORS enabled (configurable)
- URL validation
- SSL certificate verification disabled for development (configurable)
- Rate limiting available
- Request timeouts to prevent hangs

## Development

To run in development mode with auto-reloading:

```bash
FLASK_ENV=development python run.py
```

To enable debugging:

```bash
FLASK_DEBUG=1 python run.py
```

## Testing

Test endpoints using curl:

```bash
# Status check
curl "http://localhost:5000/api/status?url=google.com"

# DNS records
curl "http://localhost:5000/api/dns?url=google.com"

# SSL certificate
curl "http://localhost:5000/api/ssl?url=google.com"

# All checks at once
curl "http://localhost:5000/api/batch?url=google.com"
```

## Comparison with web-check (Node.js)

| Feature | web-check | Web-Analyzer |
|---------|-----------|--------------|
| Framework | Express.js | Flask |
| Language | JavaScript/Node.js | Python |
| Deployment | Vercel, Netlify, AWS Lambda | Traditional/Docker |
| Frontend | Astro + React/Svelte | N/A (API only) |
| Tech Stack Detection | Wappalyzer | Custom BeautifulSoup-based |
| Screenshot Support | Puppeteer | Selenium |
| Trace Route | Node traceroute | Python subprocess |
| TLS Analysis | Node tls module | Python ssl module |
| Threat Detection | VirusTotal | Google Safe Browsing, URLHaus, PhishTank, Cloudmersive |
| Archives | Wayback Machine API | Wayback Machine API |
| Carbon Analysis | Website Carbon API | Website Carbon API |
| Domain Ranking | Tranco API | Tranco + Umbrella/Alexa CSV |
| Features Detection | BuiltWith API | BuiltWith API |
| DNS Blocklists | Custom | Custom (17+ DNS providers) |
| Quality Metrics | Google PageSpeed | Google PageSpeed Insights |
| Total Endpoints | 33 | 34 (25 core + 9 external API) |

## Troubleshooting

### Connection Issues
- Verify the website is accessible
- Check firewall rules
- Ensure URL has protocol (http:// or https://)

### DNS Issues
- Some ISPs block port 53
- Try different DNS resolvers
- Check domain validity

### SSL Issues
- Some sites may use self-signed certificates
- Certificate verification can be disabled in config
- Port must be 443 for HTTPS

### Rate Limiting
- Reduce request frequency
- Wait before retrying
- Run your own instance for unlimited access

## Future Enhancements

- [ ] Screenshot capture support
- [ ] Traceroute implementation
- [ ] Security threats detection
- [ ] Google PageRank checking
- [ ] Archive snapshots
- [ ] Carbon footprint analysis
- [ ] Security scanners integration
- [ ] Performance metrics
- [ ] Database caching
- [ ] GraphQL API

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Support

For issues and questions, please open an issue on the repository.

---
- [x] Screenshot capture support
- [x] Traceroute implementation
- [x] Security threats detection (Google Safe Browsing, URLHaus, PhishTank, Cloudmersive)
- [x] Domain ranking (Tranco, Umbrella/Alexa)
- [x] Archive snapshots (Wayback Machine)
- [x] Carbon footprint analysis
- [x] DNS blocklist checking
- [x] BuiltWith features detection
- [ ] Lighthouse scores
- [ ] Virus Total integration
