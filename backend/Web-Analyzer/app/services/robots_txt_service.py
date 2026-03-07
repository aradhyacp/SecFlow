"""
Robots.txt Service - Fetch and parse robots.txt
"""
import requests
import logging
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)


def get_robots_txt(url):
    """
    Get and parse robots.txt file
    
    Args:
        url (str): The URL
        
    Returns:
        dict: Parsed robots.txt rules
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}'
    
    try:
        parsed_url = urlparse(url)
        robots_url = f'{parsed_url.scheme}://{parsed_url.hostname}/robots.txt'
        
        response = requests.get(robots_url, timeout=10, verify=False)
        
        if response.status_code != 200:
            return {
                'skipped': f'No robots.txt file present (HTTP {response.status_code})',
                'url': robots_url
            }
        
        rules = parse_robots_txt(response.text)
        
        if not rules:
            return {
                'skipped': 'No valid rules found in robots.txt',
                'url': robots_url
            }
        
        return {
            'robots': rules,
            'url': robots_url
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error fetching robots.txt: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')


def parse_robots_txt(content):
    """Parse robots.txt content into structured rules"""
    lines = content.split('\n')
    rules = []
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
        
        # Match User-agent
        ua_match = re.match(r'^User-agent:\s*(.+)$', line, re.IGNORECASE)
        if ua_match:
            rules.append({
                'type': 'User-agent',
                'value': ua_match.group(1).strip()
            })
            continue
        
        # Match Allow/Disallow
        allow_match = re.match(r'^(Allow|Disallow):\s*(.*)$', line, re.IGNORECASE)
        if allow_match:
            rules.append({
                'type': allow_match.group(1).capitalize(),
                'value': allow_match.group(2).strip()
            })
            continue
        
        # Match other directives
        other_match = re.match(r'^([^:]+):\s*(.+)$', line)
        if other_match:
            rules.append({
                'type': other_match.group(1).strip(),
                'value': other_match.group(2).strip()
            })
    
    return rules
