"""
Get IP Service - Get IP address of a domain
"""
import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def get_ip(url):
    """
    Get IP address for a domain
    
    Args:
        url (str): The URL or domain
        
    Returns:
        dict: IP address and family
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract domain from URL
    address = url.replace('https://', '').replace('http://', '').split('/')[0]
    
    try:
        # Get IP address
        ip = socket.gethostbyname(address)
        
        # Determine IP family (IPv4 or IPv6)
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            family = 6  # IPv6
        except socket.error:
            family = 4  # IPv4
        
        return {
            'ip': ip,
            'family': family,
            'address': address
        }
    
    except socket.gaierror as e:
        raise Exception(f'Unable to resolve address: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
