"""
Mail Config Service - Analyze email configuration (MX, SPF, DKIM, DMARC)
"""
import dns.resolver
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def get_mail_config(url):
    """
    Get email configuration for a domain
    
    Args:
        url (str): URL or hostname
        
    Returns:
        dict: Mail configuration (MX records, SPF, DKIM, DMARC, mail services)
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract domain
    if url.startswith('http://') or url.startswith('https://'):
        domain = urlparse(url).hostname
    else:
        domain = url.split('/')[0]
    
    if not domain:
        raise ValueError('Unable to extract domain from URL')
    
    try:
        # Get MX records
        mx_records = []
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            for mx in mx_answers:
                mx_records.append({
                    'exchange': str(mx.exchange),
                    'preference': mx.preference
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        
        # Get TXT records for email-related info
        txt_records = []
        email_txt_records = []
        mail_services = []
        
        try:
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            for txt in txt_answers:
                record_string = str(txt).strip('"')
                txt_records.append(record_string)
                
                # Check for email-related TXT records
                if (record_string.startswith('v=spf1') or
                    record_string.startswith('v=DKIM1') or
                    record_string.startswith('v=DMARC1') or
                    'protonmail-verification=' in record_string or
                    'google-site-verification=' in record_string or
                    record_string.startswith('MS=') or
                    'zoho-verification=' in record_string or
                    'titan-verification=' in record_string or
                    'bluehost.com' in record_string):
                    email_txt_records.append(record_string)
                    
                    # Identify mail service providers
                    if 'protonmail-verification=' in record_string:
                        mail_services.append({
                            'provider': 'ProtonMail',
                            'value': record_string.split('=')[1] if '=' in record_string else record_string
                        })
                    elif 'google-site-verification=' in record_string:
                        mail_services.append({
                            'provider': 'Google Workspace',
                            'value': record_string.split('=')[1] if '=' in record_string else record_string
                        })
                    elif record_string.startswith('MS='):
                        mail_services.append({
                            'provider': 'Microsoft 365',
                            'value': record_string.split('=')[1] if '=' in record_string else record_string
                        })
                    elif 'zoho-verification=' in record_string:
                        mail_services.append({
                            'provider': 'Zoho',
                            'value': record_string.split('=')[1] if '=' in record_string else record_string
                        })
                    elif 'titan-verification=' in record_string:
                        mail_services.append({
                            'provider': 'Titan',
                            'value': record_string.split('=')[1] if '=' in record_string else record_string
                        })
                    elif 'bluehost.com' in record_string:
                        mail_services.append({
                            'provider': 'BlueHost',
                            'value': record_string
                        })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        
        # Check MX records for specific providers
        for mx in mx_records:
            exchange = mx['exchange']
            if 'yahoodns.net' in exchange:
                mail_services.append({
                    'provider': 'Yahoo',
                    'value': exchange
                })
            elif 'mimecast.com' in exchange:
                mail_services.append({
                    'provider': 'Mimecast',
                    'value': exchange
                })
        
        # If no mail configuration found
        if not mx_records and not email_txt_records:
            return {'skipped': 'No mail server in use on this domain'}
        
        return {
            'mxRecords': mx_records,
            'txtRecords': email_txt_records,
            'mailServices': mail_services
        }
    
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {'skipped': 'No mail server in use on this domain'}
    except Exception as e:
        raise Exception(f'Error fetching mail configuration: {str(e)}')
