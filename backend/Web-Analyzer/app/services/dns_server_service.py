"""
DNS Server Service - Check DNS server configuration and DoH support
"""
import dns.resolver
import requests
import logging

logger = logging.getLogger(__name__)


def check_dns_server(url):
    """
    Check DNS server configuration
    
    Args:
        url (str): URL or domain
        
    Returns:
        dict: DNS server information
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract domain
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    
    try:
        # Resolve IPv4 addresses
        addresses = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            addresses = [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        
        results = []
        
        for address in addresses:
            # Try to reverse lookup
            hostname = None
            try:
                reverse_answers = dns.resolver.resolve_address(address)
                hostname = [str(rdata) for rdata in reverse_answers]
            except Exception:
                hostname = None
            
            # Check DoH (DNS-over-HTTPS) support
            doh_support = False
            try:
                doh_url = f'https://{address}/dns-query'
                response = requests.get(doh_url, timeout=3)
                if response.status_code < 500:
                    doh_support = True
            except Exception:
                doh_support = False
            
            results.append({
                'address': address,
                'hostname': hostname,
                'dohDirectSupports': doh_support
            })
        
        return {
            'domain': domain,
            'dns': results
        }
    
    except Exception as e:
        raise Exception(f'Error checking DNS server: {str(e)}')
