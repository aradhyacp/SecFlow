"""
Middleware and utility functions for API handlers
"""
import logging
from functools import wraps
from flask import jsonify
import asyncio
import time

logger = logging.getLogger(__name__)

# Configuration
TIMEOUT = 20  # seconds
ALLOWED_ORIGINS = '*'

TIMEOUT_ERROR_MSG = ('You can re-trigger this request, by clicking "Retry".\n'
                    'If you\'re running your own instance of Web-Analyzer, then you can '
                    'resolve this issue, by increasing the timeout limit in the '
                    '`API_TIMEOUT_LIMIT` environmental variable to a higher value (in seconds).\n\n'
                    f'The public instance currently has a lower timeout of {TIMEOUT}s '
                    'in order to keep running costs affordable.')


def normalize_url(url):
    """Normalize URL by adding protocol if missing"""
    if not url:
        return url
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    return url


def handle_api_error(error):
    """Convert exceptions to JSON responses"""
    error_msg = str(error)
    
    if 'timeout' in error_msg.lower():
        return {'error': TIMEOUT_ERROR_MSG}, 408
    
    return {'error': error_msg}, 400


def api_handler(f):
    """
    Decorator for API handlers to:
    - Normalize URLs
    - Handle errors
    - Return JSON responses
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            return jsonify(result), 200
        except Exception as e:
            logger.error(f'Error in {f.__name__}: {str(e)}')
            error_response, status_code = handle_api_error(e)
            return jsonify(error_response), status_code
    
    return decorated


def timeout_handler(timeout_seconds=TIMEOUT):
    """Decorator to add timeout to async functions"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # For synchronous functions
                if not asyncio.iscoroutinefunction(f):
                    return f(*args, **kwargs)
                
                # For async functions
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(
                        asyncio.wait_for(f(*args, **kwargs), timeout=timeout_seconds)
                    )
                finally:
                    loop.close()
            except asyncio.TimeoutError:
                raise Exception(f'Request timed out after {timeout_seconds} seconds')
        
        return wrapper
    
    return decorator
