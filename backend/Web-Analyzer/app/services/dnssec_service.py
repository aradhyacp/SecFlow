"""
DNSSEC Service - Check DNSSEC configuration
"""
import requests
import logging

logger = logging.getLogger(__name__)


def check_dnssec(url):
    """
    Check DNSSEC configuration using Google DNS API
    
    Args:
        url (str): URL or domain
        
    Returns:
        dict: DNSSEC records (DNSKEY, DS, RRSIG)
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract domain
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    
    dns_types = ['DNSKEY', 'DS', 'RRSIG']
    records = {}
    
    for dns_type in dns_types:
        try:
            # Use Google DNS-over-HTTPS API
            api_url = f'https://dns.google/resolve?name={domain}&type={dns_type}'
            
            response = requests.get(api_url, headers={'Accept': 'application/dns-json'}, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if 'Answer' in data and data['Answer']:
                records[dns_type] = {
                    'isFound': True,
                    'answer': data['Answer'],
                    'response': data
                }
            else:
                records[dns_type] = {
                    'isFound': False,
                    'answer': None,
                    'response': data
                }
        
        except requests.exceptions.RequestException as e:
            raise Exception(f'Error fetching {dns_type} record: {str(e)}')
        except Exception as e:
            raise Exception(f'Unexpected error for {dns_type}: {str(e)}')
    
    return records
