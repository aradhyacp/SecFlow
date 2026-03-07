"""
SSL/TLS Service - Fetch SSL certificate information
"""
import ssl
import socket
import logging
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)


def get_ssl_certificate(url):
    """
    Get SSL certificate information for a website
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: SSL certificate details
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    port = parsed_url.port or 443
    
    if not hostname:
        raise ValueError('Unable to extract hostname from URL')
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT@SECLEVEL=1')
        
        # Connect to the server
        with socket.create_connection((hostname, port), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate in DER format first
                cert = ssock.getpeercert()
                
                if not cert:
                    raise ValueError('Unable to retrieve certificate information')
                
                # Extract certificate information
                cert_info = {
                    'subject': format_cert_name(cert.get('subject', [])),
                    'issuer': format_cert_name(cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serialNumber': cert.get('serialNumber'),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                    'subjectAltName': cert.get('subjectAltName', []),
                    'keyUsage': ','.join(cert.get('keyUsage', [])) if 'keyUsage' in cert else None,
                }
                
                return cert_info
    
    except ssl.SSLError as e:
        raise ValueError(f'SSL Error: {str(e)}')
    except socket.timeout:
        raise ValueError('Connection timeout while fetching certificate')
    except Exception as e:
        raise ValueError(f'Error fetching SSL certificate: {str(e)}')


def format_cert_name(name_tuple):
    """Format certificate name tuple to dictionary"""
    result = {}
    for rdn in name_tuple:
        for name_type, name_value in rdn:
            result[name_type] = name_value
    return result
