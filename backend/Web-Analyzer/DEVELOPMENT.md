# Web-Analyzer Development Guide

## Migration from web-check (Node.js) to Web-Analyzer (Python/Flask)

This document describes how the web-check Node.js application has been migrated to Python/Flask.

## Architecture Comparison

### web-check (Node.js/Express)
```
server.js (Entry point)
├── Express app setup
├── CORS configuration
├── Rate limiting middleware
└── Dynamic route loading from /api directory
    ├── api/*.js (Individual lambda-like handlers)
    └── _common/middleware.js (Common handler logic)
```

### Web-Analyzer (Python/Flask)
```
run.py (Entry point)
├── Flask app initialization
├── CORS setup
├── Rate limiting
└── Blueprint registration
    ├── routes/api_routes.py (Route definitions)
    └── services/* (Service logic)
```

## API Endpoints Mapping

| web-check Endpoint | Web-Analyzer Endpoint | Service |
|--------------------|-----------------------|---------|
| /api/status | /api/status | status_service.py |
| /api/dns | /api/dns | dns_service.py |
| /api/ssl | /api/ssl | ssl_service.py |
| /api/headers | /api/headers | headers_service.py |
| /api/tech-stack | /api/tech-stack | tech_stack_service.py |
| /api/whois | /api/whois | whois_service.py |
| /api/robots-txt | /api/robots-txt | robots_txt_service.py |
| /api/sitemap | /api/sitemap | sitemap_service.py |
| /api/hsts | /api/hsts | hsts_service.py |
| /api/security-txt | /api/security-txt | security_txt_service.py |
| (X-headers check) | /api/security-headers | security_headers_service.py |
| /api | /api/batch | Batch endpoint |

## Key Implementation Differences

### 1. Technology Detection
**web-check:** Uses Wappalyzer library (npm package)
**Web-Analyzer:** Custom implementation using BeautifulSoup
- Parses meta tags and headers
- Checks for common framework patterns
- Extensible for custom indicators

### 2. Rate Limiting
**web-check:** Express-rate-limit middleware
**Web-Analyzer:** Custom in-memory rate limiter
- Tracks by client IP
- Configurable windows (10 min, 1 hour, 12 hours)
- Cleans old requests automatically

### 3. SSL Certificate Fetching
**web-check:** Node.js tls module
**Web-Analyzer:** Python ssl module
- Uses ssl.create_default_context()
- Socket-based connection
- Certificate parsing similar to Node.js

### 4. DNS Resolution
**web-check:** Node.js dns module
**Web-Analyzer:** dnspython library
- More comprehensive DNS record types
- Better error handling
- Direct DNS server queries

### 5. WHOIS Lookup
**web-check:** Direct socket connection to whois.internic.net
**Web-Analyzer:** Same approach with Python sockets
- Fallback parsing for structured output
- Domain extraction from URLs

### 6. HTTP Operations
**web-check:** Axios library
**Web-Analyzer:** Requests library
- Similar interface
- Better error handling
- Built-in SSL verification control

## Service Architecture

### middleware.py
Provides common utilities:
- URL normalization
- Error handling decorator
- API handler wrapper
- Timeout configuration

### Service Pattern
Each service module follows this pattern:

```python
def get_<resource>(url):
    """
    Get <resource> information
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Resource data or error message
    """
    # Validate input
    if not url:
        raise ValueError('URL parameter required')
    
    # Normalize URL
    if not url.startswith('http'):
        url = f'https://{url}'
    
    try:
        # Perform operation
        result = perform_operation(url)
        return result
    
    except Exception as e:
        raise Exception(f'Error: {str(e)}')
```

## Configuration

### Environment Variables
```bash
FLASK_ENV=development              # development or production
PORT=5000                          # Server port
API_TIMEOUT_LIMIT=20000            # Timeout in milliseconds
API_CORS_ORIGIN=*                  # CORS allowed origins
API_ENABLE_RATE_LIMIT=false        # Enable rate limiting
```

### Comparison with web-check
| Variable | web-check | Web-Analyzer |
|----------|-----------|--------------|
| PORT | 3000 | 5000 |
| API_TIMEOUT_LIMIT | milliseconds | milliseconds (converted to seconds) |
| DISABLE_EVERYTHING | VITE_DISABLE_EVERYTHING | DISABLE_EVERYTHING |
| PLATFORM detection | Auto-detect | Not needed (Flask only) |

## Error Handling

### web-check
```javascript
catch (err) {
  res.status(500).json({ error: err.message });
}
```

### Web-Analyzer
```python
except Exception as e:
    logger.error(f'Error: {str(e)}')
    return jsonify({'error': str(e)}), 400
```

## Response Format

Both maintain similar response formats:

### Success Response
```json
{
  "field1": "value1",
  "field2": "value2"
}
```

### Error Response
```json
{
  "error": "Description of error"
}
```

### Batch Response
```json
{
  "status": { ... },
  "dns": { ... },
  "ssl": { ... }
}
```

## Performance Considerations

### Caching
- No built-in caching (can be added with Flask-Caching)
- Rate limiting prevents repeated requests

### Async Operations
- Python's GIL can be mitigated with threading
- Consider Gunicorn + multiple workers for production

### Memory Usage
- Rate limit store is in-memory (can use Redis)
- Consider cleanup for long-running instances

## Testing the Migration

### Unit Testing
```bash
# Test individual endpoints
curl "http://localhost:5000/api/status?url=google.com"
curl "http://localhost:5000/api/dns?url=google.com"
curl "http://localhost:5000/api/ssl?url=google.com"
```

### Batch Testing
```bash
# Test all endpoints at once
curl "http://localhost:5000/api/batch?url=google.com"
```

### Performance Testing
```bash
# Load testing with ab (ApacheBench)
ab -n 1000 -c 10 "http://localhost:5000/api/status?url=google.com"
```

## Deployment

### Development
```bash
python run.py
```

### Production (Gunicorn)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Docker
```bash
docker build -t web-analyzer .
docker run -p 5000:5000 web-analyzer
```

### Docker Compose
```bash
docker-compose up
```

## Known Differences from web-check

### Not Implemented (Yet)
1. **Screenshot capability** - Would require Selenium or Pyppeteer
2. **Traceroute** - Requires OS-level commands
3. **Threat detection** - VirusTotal API integration needed
4. **Block lists** - Requires external data sources
5. **Performance metrics** - Requires additional instrumentation
6. **Archive snapshots** - Wayback Machine API integration
7. **Carbon footprint** - API integration needed
8. **Rank checking** - External API needed

### Advantages of Web-Analyzer
1. **Easier deployment** - No need for Vercel/Netlify
2. **Traditional hosting** - Can run on any server with Python
3. **Better DNS support** - dnspython is more comprehensive
4. **Simpler codebase** - Pure Python, no build step needed
5. **Custom tech detection** - Can be modified without external dependencies

## Future Enhancements

### Short Term
1. Add screenshot support with Selenium
2. Implement traceroute
3. Add caching with Redis
4. Performance optimization

### Medium Term
1. WebSocket support for real-time updates
2. Database integration for history
3. User authentication
4. Custom check creation
5. Scheduled checks

### Long Term
1. Machine learning for threat detection
2. Custom report generation
3. API Analytics
4. SaaS platform

## Troubleshooting

### DNS Failures
- Check if port 53 is blocked
- Test with different DNS servers
- Verify domain validity

### SSL Failures
- Some sites use self-signed certificates
- Port must be 443
- SNI required for shared hosting

### Rate Limiting Issues
- Check client IP detection
- Verify rate limit configuration
- Monitor memory usage of rate_limit_store

### Timeout Issues
- Increase API_TIMEOUT_LIMIT
- Check network connectivity
- Verify target website responsiveness

## Contributing

To add a new API endpoint:

1. Create a new service file in `app/services/`
2. Implement the handler function
3. Add import to `app/services/__init__.py`
4. Add route to `app/routes/api_routes.py`
5. Update batch endpoint
6. Test with curl
7. Update documentation

Example service file:
```python
# app/services/example_service.py
def get_example(url):
    if not url.startswith('http'):
        url = f'https://{url}'
    
    try:
        # Your implementation
        result = {}
        return result
    except Exception as e:
        raise Exception(f'Error: {str(e)}')
```

Example route:
```python
@bp.route('/example', methods=['GET'])
@check_rate_limit
@api_handler
def example():
    """Example endpoint"""
    url = get_url_param()
    return example_service.get_example(url)
```

## References

- [Flask Documentation](https://flask.palletsprojects.com/)
- [web-check Repository](https://github.com/lissy93/web-check)
- [dnspython Documentation](https://dnspython.readthedocs.io/)
- [Requests Library](https://requests.readthedocs.io/)

---

**Last Updated:** January 2026
