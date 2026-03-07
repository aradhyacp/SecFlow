"""
Security Headers Service - Check for security-related HTTP headers
"""
import requests
import logging

logger = logging.getLogger(__name__)

# List of important security headers
SECURITY_HEADERS = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Content-Security-Policy',
    'Referrer-Policy',
    'Permissions-Policy',
    'Strict-Transport-Security',
    'Expect-CT'
]


def get_security_headers(url):
    """
    Get security-related headers from a website
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Security headers present and their values
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        response = requests.head(url, timeout=10, verify=False, allow_redirects=True)
        headers = response.headers
        
        security_headers = {}
        missing_headers = []
        
        for header in SECURITY_HEADERS:
            if header in headers:
                security_headers[header] = headers[header]
            else:
                missing_headers.append(header)
        
        return {
            'present': security_headers,
            'missing': missing_headers,
            'total_present': len(security_headers),
            'total_missing': len(missing_headers),
            'score': calculate_security_score(len(security_headers), len(SECURITY_HEADERS))
        }
    
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error checking security headers: {str(e)}')


def calculate_security_score(present, total):
    """Calculate security score as percentage"""
    return round((present / total) * 100, 2)


# Alias for backward compatibility with routes
check_security_headers = get_security_headers
