"""
Cookies Service - Fetch and analyze cookies from a website
"""
import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def get_cookies(url):
    """
    Get cookies from a website
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Cookies information
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        session = requests.Session()
        response = session.get(url, timeout=10, verify=False, allow_redirects=True)
        
        # Get cookies from headers
        header_cookies = response.headers.get('Set-Cookie')
        
        # Get cookies from session
        client_cookies = []
        for cookie in session.cookies:
            client_cookies.append({
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'expires': cookie.expires,
                'secure': cookie.secure,
                'httpOnly': cookie.has_nonstandard_attr('HttpOnly')
            })
        
        if not header_cookies and not client_cookies:
            return {'skipped': 'No cookies found'}
        
        return {
            'headerCookies': header_cookies,
            'clientCookies': client_cookies
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching cookies: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
