"""
Security.txt Service - Fetch security.txt file
"""
import requests
import logging
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


def get_security_txt(url):
    """
    Get security.txt file from website
    
    Args:
        url (str): The URL
        
    Returns:
        dict: Security.txt content
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        parsed_url = urlparse(url)
        base_url = f'{parsed_url.scheme}://{parsed_url.hostname}'
        
        # Try .well-known/security.txt first
        security_url = urljoin(base_url, '/.well-known/security.txt')
        response = requests.get(security_url, timeout=10, verify=False)
        
        if response.status_code != 200:
            # Fallback to /security.txt
            security_url = urljoin(base_url, '/security.txt')
            response = requests.get(security_url, timeout=10, verify=False)
        
        if response.status_code != 200:
            return {
                'found': False,
                'message': f'security.txt not found (HTTP {response.status_code})',
                'url': security_url
            }
        
        # Parse security.txt content
        content = response.text
        fields = parse_security_txt(content)
        
        return {
            'found': True,
            'fields': fields,
            'url': security_url,
            'content': content
        }
    
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching security.txt: {str(e)}')


def parse_security_txt(content):
    """Parse security.txt content into fields"""
    fields = {}
    lines = content.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Parse key: value format
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().lower()
            value = value.strip()
            
            if key not in fields:
                fields[key] = []
            
            fields[key].append(value)
    
    return fields
