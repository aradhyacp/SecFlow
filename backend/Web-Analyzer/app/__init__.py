"""
Web-Analyzer - Flask-based Web URL Analyzer
Main application entry point
"""
import os
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import time

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Enable CORS - allow all origins for API access
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"]}})

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.config['API_TIMEOUT_LIMIT'] = int(os.getenv('API_TIMEOUT_LIMIT', 20000)) / 1000  # Convert to seconds
app.config['DISABLE_EVERYTHING'] = os.getenv('DISABLE_EVERYTHING', '').lower() == 'true'

# Rate limiting configuration
RATE_LIMIT_CONFIG = [
    {'window_seconds': 10 * 60, 'max_requests': 100, 'name': '10 minutes'},
    {'window_seconds': 60 * 60, 'max_requests': 250, 'name': '1 hour'},
    {'window_seconds': 12 * 60 * 60, 'max_requests': 500, 'name': '12 hours'},
]

# Store for rate limiting
rate_limit_store = {}


def get_client_ip():
    """Get client IP address from request"""
    if request.remote_addr:
        return request.remote_addr
    return request.headers.get('X-Forwarded-For', 'unknown').split(',')[0]


def check_rate_limit(f):
    """Decorator to check rate limits"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if os.getenv('API_ENABLE_RATE_LIMIT', '').lower() != 'true':
            return f(*args, **kwargs)
        
        client_ip = get_client_ip()
        current_time = time.time()
        
        # Initialize client in store if not exists
        if client_ip not in rate_limit_store:
            rate_limit_store[client_ip] = []
        
        # Clean old requests
        rate_limit_store[client_ip] = [
            req_time for req_time in rate_limit_store[client_ip]
            if current_time - req_time < RATE_LIMIT_CONFIG[-1]['window_seconds']
        ]
        
        # Check against each limit
        for limit in RATE_LIMIT_CONFIG:
            window_start = current_time - limit['window_seconds']
            requests_in_window = sum(1 for req_time in rate_limit_store[client_ip] if req_time >= window_start)
            
            if requests_in_window >= limit['max_requests']:
                retry_after = limit['window_seconds']
                msg = (f"You've been rate-limited, please try again in {limit['name']}.\n"
                       f"This keeps the service running smoothly for everyone. "
                       f"You can get around these limits by running your own instance of Web Analyzer.")
                return jsonify({'error': msg}), 429
        
        # Add current request
        rate_limit_store[client_ip].append(current_time)
        
        return f(*args, **kwargs)
    
    return decorated_function


@app.route('/', methods=['GET'])
def index():
    """Index route"""
    if app.config['DISABLE_EVERYTHING']:
        msg = ('Error - Web Analyzer Temporarily Disabled.\n\n'
               'We\'re sorry, but due to increased costs we\'ve had to temporarily disable the public instance. '
               'In the meantime, since our code is free and open source, '
               'you can run Web Analyzer on your own system.')
        return jsonify({'error': msg}), 503
    
    return jsonify({
        'name': 'Web-Analyzer',
        'description': 'Flask-based Web URL Analyzer',
        'version': '1.0.0',
        'endpoints': '/api',
        'docs': '/api/docs'
    })


# Register blueprints from routes
from app.routes import api_routes

app.register_blueprint(api_routes.bp)


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'Internal server error: {error}')
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
