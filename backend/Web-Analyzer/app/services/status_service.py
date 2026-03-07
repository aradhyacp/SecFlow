"""
Status Check Service - Check if a website is up and responsive
"""
import requests
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def check_status(url):
    """
    Check the status of a website
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: Contains isUp, responseTime, responseCode, dnsLookupTime
    """
    if not url:
        raise ValueError('You must provide a URL query parameter!')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        start_time = time.time()
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        end_time = time.time()
        
        response_time = (end_time - start_time) * 1000  # Convert to ms
        response_code = response.status_code
        
        if response_code < 200 or response_code >= 400:
            raise requests.exceptions.HTTPError(f'Received non-success response code: {response_code}')
        
        return {
            'isUp': True,
            'responseTime': response_time,
            'responseCode': response_code,
            'dnsLookupTime': 0,  # Would need lower-level socket operations
            'timestamp': time.time()
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error checking website status: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
