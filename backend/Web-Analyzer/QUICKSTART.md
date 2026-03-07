# Quick Start Guide - Web-Analyzer

Get up and running with Web-Analyzer in minutes!

## Option 1: Direct Installation (Fastest)

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. **Navigate to the Web-Analyzer directory**
```bash
cd /home/sunaykulkarni/IntelX/backend/Web-Analyzer
```

2. **Create a virtual environment** (recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
python run.py
```

5. **Test the API**
```bash
# In another terminal, test an endpoint:
curl "http://localhost:5000/api/status?url=google.com"
```

## Option 2: Docker (Isolated)

### Prerequisites
- Docker
- Docker Compose (optional)

### Using Docker Compose (Easiest)
```bash
# From Web-Analyzer directory
docker-compose up
```

### Using Docker Directly
```bash
# Build image
docker build -t web-analyzer .

# Run container
docker run -p 5000:5000 web-analyzer
```

## Option 3: Production Deployment

### Using Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'
```

### Using Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## API Endpoints - Quick Reference

All endpoints accept a `url` parameter:

```
http://localhost:5000/api/{endpoint}?url=example.com
```

### Available Endpoints

| Endpoint | Purpose | Example |
|----------|---------|---------|
| `/api/` | List all endpoints | |
| `/api/status` | Check if website is online | |
| `/api/dns` | Get DNS records | |
| `/api/ssl` | Get SSL certificate info | |
| `/api/headers` | Get HTTP headers | |
| `/api/tech-stack` | Detect technologies | |
| `/api/whois` | Get WHOIS data | |
| `/api/robots-txt` | Get robots.txt rules | |
| `/api/sitemap` | Get sitemap entries | |
| `/api/hsts` | Check HSTS policy | |
| `/api/security-headers` | Check security headers | |
| `/api/security-txt` | Get security.txt | |
| `/api/batch` | Run all checks | |

## Testing

### Quick Test with curl
```bash
# Basic status check
curl "http://localhost:5000/api/status?url=google.com"

# DNS records
curl "http://localhost:5000/api/dns?url=google.com"

# All endpoints at once
curl "http://localhost:5000/api/batch?url=google.com"

# Pretty print JSON (if jq installed)
curl "http://localhost:5000/api/batch?url=google.com" | jq
```

### Run Test Suite
```bash
python tests.py
```

## Configuration

Edit `.env` file to customize:

```bash
# Flask Configuration
FLASK_ENV=development        # development or production
PORT=5000                    # Server port

# API Configuration
API_TIMEOUT_LIMIT=20000      # Timeout in milliseconds
API_CORS_ORIGIN=*            # CORS allowed origins
API_ENABLE_RATE_LIMIT=false  # Enable rate limiting
```

## Common Issues

### Port Already in Use
```bash
# Use a different port
PORT=8000 python run.py

# Or kill existing process on port 5000
lsof -ti:5000 | xargs kill -9  # Linux/Mac
netstat -ano | findstr :5000   # Windows
```

### DNS Resolution Issues
- Some networks block DNS on port 53
- Try from a different network
- Check your firewall settings

### SSL Certificate Errors
- Some websites use self-signed certificates (expected)
- This is normal and doesn't indicate a problem

### Module Not Found Errors
```bash
# Make sure dependencies are installed
pip install -r requirements.txt

# Verify installation
pip list
```

## Performance Tips

### Local Testing (Development)
```bash
python run.py
```

### Production Deployment
```bash
# Install gunicorn
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 'app:app'

# Or use more workers based on CPU cores
gunicorn -w $(nproc) -b 0.0.0.0:5000 'app:app'
```

### Enable Caching (Future)
For high-traffic, consider Redis caching:
```bash
pip install Flask-Caching redis
```

## Monitoring

### Check API Status
```bash
curl http://localhost:5000/api/
```

### View Logs
```bash
# Logs appear in terminal when running with 'python run.py'
# For production, redirect to file:
python run.py > logs/app.log 2>&1 &
```

## Next Steps

1. **Read the full README** - Full documentation and API details
2. **Check DEVELOPMENT.md** - Architecture and implementation details
3. **Deploy to production** - Set up on your server
4. **Integrate with frontend** - Use the API from your frontend app
5. **Add custom features** - Extend with more services

## Integration Example

### Python Integration
```python
import requests

BASE_URL = 'http://localhost:5000/api'

def analyze_website(url):
    response = requests.get(f'{BASE_URL}/batch', params={'url': url})
    return response.json()

results = analyze_website('google.com')
print(results)
```

### JavaScript/Node.js Integration
```javascript
const BASE_URL = 'http://localhost:5000/api';

async function analyzeWebsite(url) {
    const response = await fetch(`${BASE_URL}/batch?url=${url}`);
    return await response.json();
}

analyzeWebsite('google.com').then(console.log);
```

### cURL Examples
```bash
# Simple request
curl "http://localhost:5000/api/status?url=example.com"

# Pretty JSON output (requires jq)
curl -s "http://localhost:5000/api/batch?url=example.com" | jq '.'

# Save to file
curl "http://localhost:5000/api/batch?url=example.com" > results.json

# POST request
curl -X POST http://localhost:5000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"url":"example.com"}'
```

## Troubleshooting Checklist

- [ ] Python 3.8+ installed: `python --version`
- [ ] Dependencies installed: `pip list | grep Flask`
- [ ] Port 5000 available: `lsof -i :5000`
- [ ] .env file configured
- [ ] Firewall allows connections
- [ ] Can reach external websites (for tests)
- [ ] No SSL certificate errors (expected)

## Support

For issues:
1. Check error message in console
2. Read README.md and DEVELOPMENT.md
3. Check .env configuration
4. Try restarting the application
5. Check network connectivity

## What's Next?

### Short-term
- Test all endpoints
- Integrate with your frontend
- Deploy to production

### Medium-term
- Add caching for better performance
- Enable rate limiting
- Set up monitoring

### Long-term
- Add database for history
- User authentication
- Custom check creation
- Advanced reporting

---

**Ready to go?** Run `python run.py` and visit `http://localhost:5000/api/`!
