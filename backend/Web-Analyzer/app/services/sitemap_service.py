"""
Sitemap Service - Fetch and parse sitemap.xml
"""
import requests
import logging
from urllib.parse import urlparse, urljoin
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


def get_sitemap(url):
    """
    Get and parse sitemap.xml
    
    Args:
        url (str): The URL
        
    Returns:
        dict: Parsed sitemap entries
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        parsed_url = urlparse(url)
        base_url = f'{parsed_url.scheme}://{parsed_url.hostname}'
        sitemap_url = urljoin(base_url, '/sitemap.xml')
        
        response = requests.get(sitemap_url, timeout=10, verify=False)
        
        if response.status_code != 200:
            return {
                'skipped': f'No sitemap.xml found (HTTP {response.status_code})',
                'url': sitemap_url
            }
        
        entries = parse_sitemap(response.text)
        
        return {
            'entries': entries,
            'count': len(entries),
            'url': sitemap_url
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching sitemap: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')


def parse_sitemap(content):
    """Parse sitemap XML content"""
    entries = []
    
    try:
        root = ET.fromstring(content)
        
        # Handle namespace
        namespace = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
        
        # Find all URL entries
        for url_elem in root.findall('.//sm:url', namespace):
            entry = {}
            
            loc = url_elem.find('sm:loc', namespace)
            if loc is not None:
                entry['loc'] = loc.text
            
            lastmod = url_elem.find('sm:lastmod', namespace)
            if lastmod is not None:
                entry['lastmod'] = lastmod.text
            
            changefreq = url_elem.find('sm:changefreq', namespace)
            if changefreq is not None:
                entry['changefreq'] = changefreq.text
            
            priority = url_elem.find('sm:priority', namespace)
            if priority is not None:
                entry['priority'] = priority.text
            
            if entry:
                entries.append(entry)
    
    except ET.ParseError as e:
        logger.warning(f'Error parsing sitemap XML: {str(e)}')
    
    return entries
