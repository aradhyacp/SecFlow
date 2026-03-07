"""
Tech Stack Service - Detect technologies used on a website
"""
import requests
import logging
from bs4 import BeautifulSoup
import json

logger = logging.getLogger(__name__)


def detect_tech_stack(url):
    """
    Detect technologies used on a website
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Detected technologies
    """
    if not url:
        raise ValueError('You must provide a URL query parameter!')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        technologies = {
            'cms': [],
            'frameworks': [],
            'languages': [],
            'servers': [],
            'analytics': [],
            'cdn': [],
        }
        
        # Check meta tags and headers for indicators
        headers = response.headers
        
        # Server detection
        if 'Server' in headers:
            technologies['servers'].append(headers['Server'])
        
        # Check for common frameworks
        if 'X-Powered-By' in headers:
            tech = headers['X-Powered-By']
            if 'php' in tech.lower():
                technologies['languages'].append('PHP')
            elif 'aspnet' in tech.lower():
                technologies['languages'].append('ASP.NET')
            else:
                technologies['frameworks'].append(tech)
        
        # Check meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            name = meta.get('name', '').lower()
            content = meta.get('content', '')
            
            if 'generator' in name and content:
                technologies['cms'].append(content)
        
        # Check for common framework indicators in HTML
        html_content = response.text.lower()
        
        common_indicators = {
            'React': ['react', 'reactjs', '__react'],
            'Vue': ['vue', 'vuejs', '__vue'],
            'Angular': ['angular', 'ng-app'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['sites/default', 'modules/system'],
            'Joomla': ['components/com_'],
        }
        
        for tech, patterns in common_indicators.items():
            for pattern in patterns:
                if pattern in html_content:
                    if tech not in technologies['frameworks'] and tech not in technologies['cms']:
                        technologies['frameworks'].append(tech)
                    break
        
        return {
            'technologies': technologies,
            'url': url,
            'status': 'success'
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching website: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
