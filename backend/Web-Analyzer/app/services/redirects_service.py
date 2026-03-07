"""
Redirects Service - Trace URL redirects
"""
import requests
import logging

logger = logging.getLogger(__name__)


def get_redirects(url):
    """
    Get redirect chain for a URL
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: List of redirects
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        redirects = [url]
        
        # Create a session to track redirects
        session = requests.Session()
        session.max_redirects = 12
        
        # Custom redirect handler
        response = session.get(url, timeout=10, verify=False, allow_redirects=True)
        
        # Get redirect history
        for resp in response.history:
            if 'Location' in resp.headers:
                redirects.append(resp.headers['Location'])
        
        # Add final URL if different
        if response.url not in redirects:
            redirects.append(response.url)
        
        return {'redirects': redirects}
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error tracing redirects: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
