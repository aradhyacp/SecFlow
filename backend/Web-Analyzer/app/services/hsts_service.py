"""
HSTS Service - Check for HTTP Strict Transport Security headers
"""
import requests
import logging

logger = logging.getLogger(__name__)


def get_hsts_policy(url):
    """
    Get HSTS (HTTP Strict Transport Security) policy
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: HSTS policy details
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        response = requests.head(url, timeout=10, verify=False, allow_redirects=True)
        headers = response.headers
        
        hsts_header = headers.get('Strict-Transport-Security')
        
        if not hsts_header:
            return {
                'present': False,
                'policy': None,
                'message': 'HSTS header not found'
            }
        
        # Parse HSTS header
        policy = parse_hsts_header(hsts_header)
        
        return {
            'present': True,
            'policy': policy,
            'rawHeader': hsts_header
        }
    
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error checking HSTS: {str(e)}')


def parse_hsts_header(header):
    """Parse HSTS header value"""
    policy = {}
    parts = header.split(';')
    
    for part in parts:
        part = part.strip()
        
        if part.startswith('max-age='):
            policy['max_age'] = int(part.split('=')[1])
        elif part.lower() == 'includesubdomains':
            policy['includeSubDomains'] = True
        elif part.lower() == 'preload':
            policy['preload'] = True
    
    return policy
