"""
TLS Service - Check TLS configuration using SSL socket connection
"""
import socket
import ssl as ssl_module
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def check_tls(url):
    """
    Check TLS configuration using SSL socket connection
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: TLS configuration results
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract domain
    if url.startswith('http://') or url.startswith('https://'):
        domain = urlparse(url).hostname
    else:
        domain = url.split('/')[0]
    
    if not domain:
        raise ValueError('Unable to extract domain from URL')
    
    try:
        # Create SSL context
        context = ssl_module.create_default_context()
        
        # Connect and get TLS info
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                cert = ssock.getpeercert()
                
                return {
                    'domain': domain,
                    'tlsVersion': version,
                    'cipher': {
                        'name': cipher[0] if cipher else None,
                        'protocol': cipher[1] if cipher else None,
                        'bits': cipher[2] if cipher else None
                    },
                    'validCertificate': cert is not None,
                    'certificateIssuer': dict(item[0] for item in cert.get('issuer', [])) if cert else None
                }
    
    except socket.timeout:
        raise Exception('Connection timeout while checking TLS')
    except Exception as e:
        raise Exception(f'Error checking TLS configuration: {str(e)}')
