"""
Linked Pages Service - Extract internal and external links from a page
"""
import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import Counter

logger = logging.getLogger(__name__)


def get_linked_pages(url):
    """
    Extract internal and external links from a webpage
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Internal and external links
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        internal_links_map = Counter()
        external_links_map = Counter()
        
        # Get all anchor tags with href
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            
            # Convert to absolute URL
            absolute_url = urljoin(url, href)
            
            # Check if internal or external
            if absolute_url.startswith(url):
                internal_links_map[absolute_url] += 1
            elif href.startswith('http://') or href.startswith('https://'):
                external_links_map[absolute_url] += 1
        
        # Sort by occurrence and get unique URLs
        internal_links = [link for link, count in internal_links_map.most_common()]
        external_links = [link for link, count in external_links_map.most_common()]
        
        # Check if no links found
        if not internal_links and not external_links:
            return {
                'skipped': 'No internal or external links found. '
                          'This may be due to the website being dynamically rendered.'
            }
        
        return {
            'internal': internal_links,
            'external': external_links
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching page: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
