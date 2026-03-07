"""
Firewall Service - Detect Web Application Firewall (WAF)
"""
import requests
import logging

logger = logging.getLogger(__name__)


def detect_firewall(url):
    """
    Detect Web Application Firewall (WAF) from HTTP headers
    
    Args:
        url (str): The URL to check
        
    Returns:
        dict: WAF detection result
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'http://{url}'
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        
        # Check for various WAF signatures
        waf_signatures = [
            ('Cloudflare', lambda h: 'cloudflare' in h.get('server', '').lower()),
            ('AWS WAF', lambda h: 'AWS Lambda' in h.get('x-powered-by', '')),
            ('Akamai', lambda h: 'AkamaiGHost' in h.get('server', '')),
            ('Sucuri', lambda h: 'Sucuri' in h.get('server', '') or 'x-sucuri-id' in h or 'x-sucuri-cache' in h),
            ('Barracuda WAF', lambda h: 'BarracudaWAF' in h.get('server', '')),
            ('F5 BIG-IP', lambda h: 'F5 BIG-IP' in h.get('server', '') or 'BIG-IP' in h.get('server', '')),
            ('FortiWeb', lambda h: 'FortiWeb' in h.get('server', '')),
            ('Imperva', lambda h: 'Imperva' in h.get('server', '')),
            ('Sqreen', lambda h: 'Sqreen' in h.get('x-protected-by', '')),
            ('Reblaze WAF', lambda h: 'x-waf-event-info' in h),
            ('Citrix NetScaler', lambda h: '_citrix_ns_id' in h.get('set-cookie', '')),
            ('WangZhanBao WAF', lambda h: 'x-denied-reason' in h or 'x-wzws-requested-method' in h),
            ('Webcoment Firewall', lambda h: 'x-webcoment' in h),
            ('Yundun WAF', lambda h: 'Yundun' in h.get('server', '') or 'x-yd-waf-info' in h or 'x-yd-info' in h),
            ('ModSecurity', lambda h: 'Mod_Security' in h.get('server', '')),
            ('AWS Shield', lambda h: 'x-amz-cf-id' in h),
            ('Wordfence', lambda h: 'wordfence' in h.get('server', '').lower()),
        ]
        
        for waf_name, check_func in waf_signatures:
            if check_func(headers):
                return {
                    'hasWaf': True,
                    'waf': waf_name
                }
        
        return {
            'hasWaf': False,
            'waf': None,
            'message': 'No WAF detected'
        }
    
    except requests.exceptions.Timeout:
        raise Exception(f'Request timeout for {url}')
    except requests.exceptions.RequestException as e:
        raise Exception(f'Error checking firewall: {str(e)}')
    except Exception as e:
        raise Exception(f'Unexpected error: {str(e)}')
