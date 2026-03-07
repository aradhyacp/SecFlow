#!/usr/bin/env python3
"""
Main entry point for Web-Analyzer Flask application
"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'production') == 'development'
    
    print(f"Starting Web-Analyzer on port {port}...")
    print(f"API available at http://localhost:{port}/api/web-analyzer")
    
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
