"""
Social Tags Service - Extract social media meta tags from a website
"""
import requests
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def get_social_tags(url):
    """
    Extract social media meta tags (OpenGraph, Twitter Cards, etc.)
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Social media tags
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'http://{url}'
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        metadata = {}
        
        # Basic meta tags
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.get_text()
        
        # Helper function to get meta content
        def get_meta_content(name=None, property=None):
            if name:
                tag = soup.find('meta', attrs={'name': name})
            elif property:
                tag = soup.find('meta', attrs={'property': property})
            else:
                return None
            return tag.get('content') if tag else None
        
        # Basic meta tags
        metadata['description'] = get_meta_content(name='description')
        metadata['keywords'] = get_meta_content(name='keywords')
        
        # Canonical URL
        canonical = soup.find('link', attrs={'rel': 'canonical'})
        metadata['canonicalUrl'] = canonical.get('href') if canonical else None
        
        # OpenGraph Protocol
        metadata['ogTitle'] = get_meta_content(property='og:title')
        metadata['ogType'] = get_meta_content(property='og:type')
        metadata['ogImage'] = get_meta_content(property='og:image')
        metadata['ogUrl'] = get_meta_content(property='og:url')
        metadata['ogDescription'] = get_meta_content(property='og:description')
        metadata['ogSiteName'] = get_meta_content(property='og:site_name')
        
        # Twitter Cards
        metadata['twitterCard'] = get_meta_content(name='twitter:card')
        metadata['twitterSite'] = get_meta_content(name='twitter:site')
        metadata['twitterCreator'] = get_meta_content(name='twitter:creator')
        metadata['twitterTitle'] = get_meta_content(name='twitter:title')
        metadata['twitterDescription'] = get_meta_content(name='twitter:description')
        metadata['twitterImage'] = get_meta_content(name='twitter:image')
        
        # Misc tags
        metadata['themeColor'] = get_meta_content(name='theme-color')
        metadata['robots'] = get_meta_content(name='robots')
        metadata['googlebot'] = get_meta_content(name='googlebot')
        metadata['generator'] = get_meta_content(name='generator')
        metadata['viewport'] = get_meta_content(name='viewport')
        metadata['author'] = get_meta_content(name='author')
        
        # Publisher link
        publisher = soup.find('link', attrs={'rel': 'publisher'})
        metadata['publisher'] = publisher.get('href') if publisher else None
        
        # Favicon
        favicon = soup.find('link', attrs={'rel': 'icon'})
        metadata['favicon'] = favicon.get('href') if favicon else None
        
        # Filter out None values
        metadata = {k: v for k, v in metadata.items() if v is not None}
        
        if not metadata:
            return {'skipped': 'No metadata found'}
        
        return metadata
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching website: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
