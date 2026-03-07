"""
DNS Service - Fetch DNS records for a domain
"""
import dns.resolver
import dns.rdatatype
import logging

logger = logging.getLogger(__name__)


def get_dns_records(url):
    """
    Get DNS records for a domain
    
    Args:
        url (str): URL or hostname
        
    Returns:
        dict: Contains A, AAAA, MX, TXT, NS, CNAME, SOA, SRV, PTR records
    """
    hostname = url
    
    # Handle URLs by extracting hostname
    if hostname.startswith('http://') or hostname.startswith('https://'):
        from urllib.parse import urlparse
        hostname = urlparse(hostname).hostname
    
    if not hostname:
        raise ValueError('Unable to extract hostname from URL')
    
    result = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'PTR']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(hostname, record_type, raise_on_no_answer=False)
            records = []
            
            for answer in answers:
                if record_type == 'MX':
                    records.append({
                        'exchange': str(answer.exchange),
                        'preference': answer.preference
                    })
                elif record_type == 'SOA':
                    records.append({
                        'mname': str(answer.mname),
                        'rname': str(answer.rname),
                        'serial': answer.serial,
                        'refresh': answer.refresh,
                        'retry': answer.retry,
                        'expire': answer.expire,
                        'minimum': answer.minimum
                    })
                elif record_type == 'SRV':
                    records.append({
                        'priority': answer.priority,
                        'weight': answer.weight,
                        'port': answer.port,
                        'target': str(answer.target)
                    })
                else:
                    records.append(str(answer))
            
            result[record_type] = records if records else []
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            result[record_type] = []
        except Exception as e:
            logger.warning(f'Error fetching {record_type} record for {hostname}: {str(e)}')
            result[record_type] = []
    
    return result
