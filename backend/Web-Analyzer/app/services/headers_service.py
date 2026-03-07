"""
Headers Service - Fetch HTTP headers from a website
"""
import requests
import logging

logger = logging.getLogger(__name__)


def get_headers(url):
    """
    Get HTTP headers from a website
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: HTTP headers
    """
    if not url:
        raise ValueError('You must provide a URL query parameter!')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
        
        # Convert headers to dict
        headers_dict = dict(response.headers)
        
        return headers_dict
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching headers: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
