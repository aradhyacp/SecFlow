"""
TXT Records Service - Fetch TXT DNS records
"""
import dns.resolver
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def get_txt_records(url):
    """
    Get TXT DNS records for a domain
    
    Args:
        url (str): URL or hostname
        
    Returns:
        dict: TXT records in readable format
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract hostname
    if url.startswith('http://') or url.startswith('https://'):
        hostname = urlparse(url).hostname
    else:
        hostname = url.split('/')[0]
    
    if not hostname:
        raise ValueError('Unable to extract hostname from URL')
    
    try:
        answers = dns.resolver.resolve(hostname, 'TXT', raise_on_no_answer=False)
        
        # Parse TXT records into key-value pairs
        readable_records = {}
        
        for answer in answers:
            # TXT records come as strings, often with key=value format
            txt_string = str(answer).strip('"')
            
            # Try to parse as key=value
            if '=' in txt_string:
                parts = txt_string.split('=', 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ''
                readable_records[key] = value
            else:
                # If not key=value format, use index as key
                readable_records[f'record_{len(readable_records)}'] = txt_string
        
        return readable_records
    
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {'message': 'No TXT records found'}
    except Exception as e:
        raise Exception(f'Error fetching TXT records: {str(e)}')
