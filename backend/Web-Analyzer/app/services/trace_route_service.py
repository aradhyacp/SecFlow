"""
Trace Route Service - Trace network route to a host
"""
import subprocess
import logging
import socket
import json
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def trace_route(url):
    """
    Trace network route to a host
    Falls back to DNS + network info if traceroute command unavailable
    
    Args:
        url (str): The URL or hostname
        
    Returns:
        dict: Trace route hops or network information
    """
    if not url:
        raise ValueError('URL parameter is required')
    
    # Extract hostname
    if url.startswith('http://') or url.startswith('https://'):
        hostname = urlparse(url).hostname
    else:
        hostname = url.split('/')[0]
    
    if not hostname:
        raise ValueError('Unable to extract hostname from URL')
    
    try:
        # Try to use native traceroute command first
        return attempt_native_traceroute(hostname)
    except Exception as e:
        logger.info(f"Native traceroute failed, using fallback: {str(e)}")
        # Fallback to DNS + network info
        return get_traceroute_fallback(hostname)


def attempt_native_traceroute(hostname):
    """
    Attempt to run native traceroute command
    
    Args:
        hostname (str): The hostname to trace
        
    Returns:
        dict: Traceroute results
    """
    import platform
    import shutil
    
    if platform.system() == 'Windows':
        cmd = ['tracert', '-h', '30', hostname]
        cmd_name = 'tracert'
    else:
        cmd = ['traceroute', '-m', '30', hostname]
        cmd_name = 'traceroute'
    
    # Check if command exists
    if not shutil.which(cmd_name):
        raise FileNotFoundError(f'{cmd_name} command not available')
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30
    )
    
    if result.returncode != 0:
        raise Exception(f'Traceroute failed: {result.stderr}')
    
    hops = parse_traceroute_output(result.stdout)
    
    return {
        'message': 'Traceroute completed!',
        'result': hops
    }


def get_traceroute_fallback(hostname):
    """
    Fallback traceroute using DNS resolution and network info
    
    Args:
        hostname (str): The hostname to trace
        
    Returns:
        dict: Network routing information
    """
    try:
        # Resolve hostname to IP
        ip_address = socket.gethostbyname(hostname)
        
        # Try to get network info via nslookup or dig if available
        import shutil
        
        hops = []
        
        # Add starting point
        hops.append({
            'hop': 1,
            'info': 'Local gateway',
            'type': 'gateway'
        })
        
        # Add destination
        hops.append({
            'hop': 2,
            'hostname': hostname,
            'ip': ip_address,
            'type': 'destination'
        })
        
        # Try to get NS records (nameservers)
        try:
            ns_records = socket.getfqdn(hostname)
            hops.append({
                'hop': 3,
                'info': f'Nameserver: {ns_records}',
                'type': 'nameserver'
            })
        except:
            pass
        
        return {
            'message': 'Traceroute unavailable - returned network resolution info',
            'hostname': hostname,
            'resolved_ip': ip_address,
            'hops': hops,
            'note': 'Full traceroute not available. Install traceroute/tracert command for complete path information.'
        }
        
    except socket.gaierror as e:
        return {
            'error': f'Could not resolve hostname: {str(e)}',
            'hostname': hostname
        }
    except Exception as e:
        return {
            'error': f'Network trace failed: {str(e)}',
            'hostname': hostname
        }


def parse_traceroute_output(output):
    """Parse traceroute output into structured format"""
    import re
    
    hops = []
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Try to extract hop number and IP/hostname
        # Format varies by OS
        match = re.search(r'(\d+)\s+(.+)', line)
        if match:
            hop_num = match.group(1)
            hop_info = match.group(2).strip()
            
            hops.append({
                'hop': int(hop_num),
                'info': hop_info
            })
    
    return hops
    
    return hops
