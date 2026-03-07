"""
Ports Service - Check open ports on a domain
"""
import socket
import logging
from urllib.parse import urlparse
import concurrent.futures

logger = logging.getLogger(__name__)


# Default commonly used ports
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 67, 68, 69,
    110, 119, 123, 143, 156, 161, 162, 179, 194,
    389, 443, 587, 993, 995,
    3000, 3306, 3389, 5060, 5900, 8000, 8080, 8888
]


def check_port(host, port, timeout=1.5):
    """Check if a specific port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except Exception as e:
        logger.debug(f'Error checking port {port}: {str(e)}')
        return None


def scan_ports(url):
    """
    Scan common ports on a domain
    
    Args:
        url (str): The URL to scan
        
    Returns:
        dict: Open and closed ports
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract domain from URL
    domain = url.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        # Resolve domain to IP
        host = socket.gethostbyname(domain)
        
        open_ports = []
        closed_ports = []
        
        # Use thread pool for parallel port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(check_port, host, port): port for port in DEFAULT_PORTS}
            
            for future in concurrent.futures.as_completed(future_to_port, timeout=9):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                    else:
                        closed_ports.append(port)
                except Exception:
                    closed_ports.append(port)
        
        return {
            'host': host,
            'openPorts': sorted(open_ports),
            'closedPorts': sorted(closed_ports)
        }
    
    except socket.gaierror:
        raise Exception(f'Unable to resolve domain: {domain}')
    except Exception as e:
        raise Exception(f'Error scanning ports: {str(e)}')
