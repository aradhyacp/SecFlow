"""
DNS Block Lists Service
Checks if a domain is blocked by various DNS providers (parental controls, security filters)
"""
import dns.resolver
from typing import Dict, Any, List
from urllib.parse import urlparse
import socket


DNS_SERVERS = [
    {"name": "AdGuard", "ip": "176.103.130.130"},
    {"name": "AdGuard Family", "ip": "176.103.130.132"},
    {"name": "CleanBrowsing Adult", "ip": "185.228.168.10"},
    {"name": "CleanBrowsing Family", "ip": "185.228.168.168"},
    {"name": "CleanBrowsing Security", "ip": "185.228.168.9"},
    {"name": "CloudFlare", "ip": "1.1.1.1"},
    {"name": "CloudFlare Family", "ip": "1.1.1.3"},
    {"name": "Comodo Secure", "ip": "8.26.56.26"},
    {"name": "Google DNS", "ip": "8.8.8.8"},
    {"name": "Neustar Family", "ip": "156.154.70.3"},
    {"name": "Neustar Protection", "ip": "156.154.70.2"},
    {"name": "Norton Family", "ip": "199.85.126.20"},
    {"name": "OpenDNS", "ip": "208.67.222.222"},
    {"name": "OpenDNS Family", "ip": "208.67.222.123"},
    {"name": "Quad9", "ip": "9.9.9.9"},
    {"name": "Yandex Family", "ip": "77.88.8.7"},
    {"name": "Yandex Safe", "ip": "77.88.8.88"},
]

KNOWN_BLOCK_IPS = [
    '146.112.61.106',  # OpenDNS
    '185.228.168.10',  # CleanBrowsing
    '8.26.56.26',      # Comodo
    '9.9.9.9',         # Quad9
    '208.69.38.170',   # Some OpenDNS IPs
    '208.69.39.170',   # Some OpenDNS IPs
    '208.67.222.222',  # OpenDNS
    '208.67.222.123',  # OpenDNS FamilyShield
    '199.85.126.10',   # Norton
    '199.85.126.20',   # Norton Family
    '156.154.70.22',   # Neustar
    '77.88.8.7',       # Yandex
    '77.88.8.8',       # Yandex
    '::1',             # Localhost IPv6
    '2a02:6b8::feed:0ff',    # Yandex DNS
    '2a02:6b8::feed:bad',    # Yandex Safe
    '2a02:6b8::feed:a11',    # Yandex Family
    '2620:119:35::35',       # OpenDNS
    '2620:119:53::53',       # OpenDNS FamilyShield
    '2606:4700:4700::1111',  # Cloudflare
    '2606:4700:4700::1001',  # Cloudflare
    '2001:4860:4860::8888',  # Google DNS
    '2a0d:2a00:1::',         # AdGuard
    '2a0d:2a00:2::',         # AdGuard Family
]


def is_domain_blocked(domain: str, server_ip: str) -> bool:
    """Check if domain is blocked by a specific DNS server"""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.timeout = 3
    resolver.lifetime = 3
    
    try:
        # Try IPv4 resolution
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            if str(rdata) in KNOWN_BLOCK_IPS:
                return True
        return False
        
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        # Try IPv6 resolution as fallback
        try:
            answers = resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                if str(rdata) in KNOWN_BLOCK_IPS:
                    return True
            return False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # If domain doesn't exist or times out, consider it blocked
            return True
        except Exception:
            return False
    except Exception:
        return False


def check_domain_against_dns_servers(domain: str) -> List[Dict[str, Any]]:
    """Check domain against all DNS servers"""
    results = []
    
    for server in DNS_SERVERS:
        is_blocked = is_domain_blocked(domain, server['ip'])
        results.append({
            "server": server['name'],
            "serverIp": server['ip'],
            "isBlocked": is_blocked
        })
    
    return results


def get_block_lists(url: str) -> Dict[str, Any]:
    """
    Check if domain is blocked by various DNS providers
    
    Args:
        url: The URL to check
        
    Returns:
        Dictionary containing block list results from all DNS servers
    """
    try:
        domain = urlparse(url).hostname
        if not domain:
            raise Exception('Invalid URL')
        
        results = check_domain_against_dns_servers(domain)
        return {"blocklists": results}
        
    except Exception as e:
        raise Exception(f"Error checking block lists: {str(e)}")
