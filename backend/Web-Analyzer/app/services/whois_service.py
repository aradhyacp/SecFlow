"""
Whois Service - Fetch WHOIS information for a domain
"""
import socket
import logging
import re
from urllib.parse import urlparse
import requests

logger = logging.getLogger(__name__)


def get_whois_data(url):
    """
    Get WHOIS information for a domain
    
    Args:
        url (str): URL or hostname
        
    Returns:
        dict: WHOIS data
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'http://{url}'
    
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        # Get base domain
        parts = hostname.split('.')
        if len(parts) > 2:
            domain = '.'.join(parts[-2:])
        else:
            domain = hostname
        
        # Try to fetch from WHOIS server
        whois_data = fetch_from_whois_server(domain)
        
        return {
            'domain': domain,
            'whois_data': parse_whois_data(whois_data),
            'source': 'whois.internic.net'
        }
    
    except Exception as e:
        raise Exception(f'Error fetching WHOIS data: {str(e)}')


def fetch_from_whois_server(domain, server='whois.internic.net', port=43):
    """Fetch WHOIS data from WHOIS server"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))
        sock.send(f'{domain}\r\n'.encode())
        
        data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        
        sock.close()
        return data.decode('utf-8', errors='ignore')
    
    except Exception as e:
        logger.warning(f'Failed to fetch from WHOIS server: {str(e)}')
        return ''


def parse_whois_data(data):
    """Parse WHOIS data into structured format"""
    if not data or 'No match for' in data:
        return {'error': 'No matches found for domain in WHOIS database'}
    
    parsed = {}
    lines = data.split('\n')
    last_key = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip().replace(' ', '_').lower()
            value = value.strip()
            
            if key and value:
                last_key = key
                parsed[key] = value
        elif last_key:
            # Continuation of previous value
            parsed[last_key] += ' ' + line
    
    return parsed
