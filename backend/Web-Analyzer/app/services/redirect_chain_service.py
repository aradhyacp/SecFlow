"""
Redirect Chain Service - Deep analysis of URL redirect chains with hop classification and risk scoring.
Ported from Url-Analyzer.
"""
import requests
import socket
import logging
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


class RedirectChainAnalyzer:
    """Analyze URL redirect chains and provide detailed hop information"""

    def __init__(self, timeout=10, max_hops=20):
        self.timeout = timeout
        self.max_hops = max_hops
        self.session = requests.Session()

    def analyze(self, url: str) -> dict:
        """Analyze URL redirect chain"""
        try:
            redirect_chain = []
            current_url = url
            visited = set()

            if not current_url.startswith(('http://', 'https://')):
                current_url = 'https://' + current_url

            for hop_num in range(1, self.max_hops + 1):
                if current_url in visited:
                    logger.warning(f"Circular redirect detected at hop {hop_num}")
                    break

                visited.add(current_url)

                try:
                    response = self.session.get(
                        current_url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                        verify=True,
                        stream=True
                    )
                    response.close()

                    parsed = urlparse(current_url)
                    ip = self._resolve_hostname(parsed.hostname)

                    hop_info = {
                        'hop': hop_num,
                        'url': current_url,
                        'resolved_ip': ip,
                        'status_code': response.status_code,
                        'protocol': parsed.scheme,
                        'domain': parsed.hostname,
                        'is_https': parsed.scheme == 'https',
                        'types': self._classify_hop(current_url, response.status_code, hop_num, len(visited)),
                        'notes': self._generate_notes(current_url, response.status_code, hop_num)
                    }

                    if response.status_code in [301, 302, 303, 307, 308]:
                        next_url = response.headers.get('Location')
                        if next_url:
                            if not next_url.startswith(('http://', 'https://')):
                                next_url = urljoin(current_url, next_url)

                            hop_info['redirects_to'] = next_url

                            next_domain = urlparse(next_url).hostname
                            if next_domain and next_domain != parsed.hostname:
                                if 'Cross-Domain Redirect' not in hop_info['types']:
                                    hop_info['types'].append('Cross-Domain Redirect')

                            redirect_chain.append(hop_info)
                            current_url = next_url
                        else:
                            redirect_chain.append(hop_info)
                            break
                    else:
                        redirect_chain.append(hop_info)
                        break

                except requests.exceptions.Timeout:
                    redirect_chain.append({
                        'hop': hop_num, 'url': current_url,
                        'error': 'Connection timeout', 'types': ['Timeout'],
                        'notes': ['Request timed out']
                    })
                    break
                except requests.exceptions.SSLError as e:
                    redirect_chain.append({
                        'hop': hop_num, 'url': current_url,
                        'error': f'SSL error: {str(e)}', 'types': ['SSL Error'],
                        'notes': ['SSL/TLS certificate verification failed']
                    })
                    break
                except requests.exceptions.ConnectionError as e:
                    redirect_chain.append({
                        'hop': hop_num, 'url': current_url,
                        'error': f'Connection error: {str(e)}', 'types': ['Connection Error'],
                        'notes': ['Could not connect to the URL']
                    })
                    break
                except requests.exceptions.RequestException:
                    break

            final_hop = redirect_chain[-1] if redirect_chain else None
            final_destination = None

            if final_hop and 'error' not in final_hop:
                final_destination = {
                    'url': final_hop.get('url'),
                    'domain': final_hop.get('domain'),
                    'ip': final_hop.get('resolved_ip'),
                    'uses_https': final_hop.get('is_https'),
                    'status_code': final_hop.get('status_code')
                }

            risk_assessment = self._assess_risk(redirect_chain, url, final_hop)

            return {
                'original_url': url,
                'total_hops': len(redirect_chain),
                'redirect_chain': redirect_chain,
                'final_destination': final_destination,
                'risk_assessment': risk_assessment,
                'is_safe': risk_assessment['level'] == 'low',
                'limitations': [
                    'JavaScript-based redirects are not analyzed',
                    'Analysis limited to server-side HTTP redirects'
                ]
            }

        except Exception as e:
            logger.error(f"Error analyzing redirect chain: {str(e)}")
            return {
                'original_url': url,
                'error': str(e),
                'redirect_chain': [],
                'total_hops': 0,
                'is_safe': False
            }

    def _resolve_hostname(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def _classify_hop(self, url, status_code, hop_num, total_hops):
        types = []
        parsed = urlparse(url)
        domain = parsed.hostname.lower() if parsed.hostname else ''

        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'short.link', 'ow.ly', 'buff.ly',
                      'shorturl.at', 't.co', 'is.gd', 'tr.im', 'vu.ma', 'adf.ly']
        if any(short in domain for short in shorteners):
            types.append('URL Shortener')

        tracking_keywords = ['tracking', 'analytics', 'utm', 'click', 'redirect', 'ad', 'ads']
        if any(keyword in domain or keyword in parsed.query for keyword in tracking_keywords):
            types.append('Tracking Redirect')

        redirect_map = {301: 'Permanent Redirect', 302: 'Temporary Redirect',
                        303: 'See Other Redirect', 307: 'Temporary Redirect', 308: 'Permanent Redirect'}
        if status_code in redirect_map:
            types.append(redirect_map[status_code])

        if parsed.scheme == 'http':
            types.append('HTTP Redirect')

        if status_code not in [301, 302, 303, 307, 308]:
            types.append('Final Destination')

        return types if types else ['Other']

    def _generate_notes(self, url, status_code, hop_num):
        notes = []
        parsed = urlparse(url)
        domain = parsed.hostname.lower() if parsed.hostname else ''

        shorteners = {
            'bit.ly': 'Known URL shortening service',
            'tinyurl.com': 'Known URL shortening service',
            'goo.gl': 'Known URL shortening service',
            'short.link': 'Known URL shortening service',
            'ow.ly': 'Known URL shortening service',
        }
        for shortener, desc in shorteners.items():
            if shortener in domain:
                notes.append(desc)

        if parsed.scheme == 'http':
            notes.append('Unencrypted HTTP connection')

        redirect_notes = {301: 'Permanent redirect detected', 302: 'Temporary redirect detected',
                          307: 'Temporary redirect detected', 308: 'Temporary redirect detected'}
        if status_code in redirect_notes:
            notes.append(redirect_notes[status_code])

        if parsed.query and any(t in parsed.query for t in ['utm_', 'fbclid', 'gclid']):
            notes.append('Tracking parameters detected in query string')

        suspicious = ['login', 'verify', 'confirm', 'update', 'account', 'admin']
        if any(kw in domain or kw in parsed.path.lower() for kw in suspicious):
            notes.append('Suspicious keywords detected in domain or path')

        return notes if notes else ['Standard redirect']

    def _assess_risk(self, redirect_chain, original_url, final_hop=None):
        score = 100
        reasons = []

        if not redirect_chain:
            return {'level': 'medium', 'score': 50, 'reasons': ['Unable to analyze URL']}

        if final_hop and 'error' in final_hop:
            return {
                'level': 'high', 'score': 30,
                'reasons': [f'Final destination error: {final_hop.get("error", "Unknown error")}']
            }

        redirect_count = len([h for h in redirect_chain if 'redirects_to' in h])
        if redirect_count > 5:
            score -= 20; reasons.append('Excessive number of redirects (>5)')
        elif redirect_count > 3:
            score -= 15; reasons.append('Multiple redirects detected (>3)')
        elif redirect_count > 1:
            score -= 10; reasons.append('Multiple redirects detected')
        elif redirect_count == 1:
            score -= 3

        original_domain = urlparse(original_url).hostname or ''
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'short.link', 'ow.ly', 'buff.ly',
                      'shorturl.at', 't.co', 'is.gd', 'tr.im', 'vu.ma', 'adf.ly']
        if any(short in original_domain.lower() for short in shorteners):
            score -= 20; reasons.append('URL shortener used in original URL')

        tracking_keywords = ['tracking', 'analytics', 'utm', 'click', 'redirect', 'ad', 'ads']
        suspicious_domains = []
        for hop in redirect_chain:
            domain = hop.get('domain', '').lower() if hop.get('domain') else ''
            if any(kw in domain for kw in tracking_keywords):
                suspicious_domains.append(domain)
                score -= 8
        if suspicious_domains:
            reasons.append(f'Tracking/suspicious domains: {", ".join(set(suspicious_domains))}')

        cross_domain_count = 0
        for hop in redirect_chain:
            if 'redirects_to' in hop:
                next_url = hop['redirects_to']
                current_domain = hop.get('domain', '')
                next_domain = urlparse(next_url).hostname
                if current_domain and next_domain and current_domain != next_domain:
                    cross_domain_count += 1

        if cross_domain_count > 3:
            score -= 15; reasons.append(f'Many cross-domain redirects ({cross_domain_count})')
        elif cross_domain_count > 1:
            score -= 10; reasons.append(f'Multiple cross-domain redirects ({cross_domain_count})')
        elif cross_domain_count == 1:
            score -= 5; reasons.append('Cross-domain redirect detected')

        http_hops = [h for h in redirect_chain if h.get('protocol') == 'http']
        if http_hops:
            score -= 15; reasons.append(f'Unencrypted HTTP found in {len(http_hops)} hop(s)')

        final = redirect_chain[-1]
        if final.get('protocol') == 'http':
            score -= 10; reasons.append('Final destination is not HTTPS')

        final_domain = final.get('domain', '').lower() if final.get('domain') else ''
        final_path = urlparse(final.get('url', '')).path.lower()
        suspicious_kw = ['login', 'verify', 'confirm', 'update', 'account', 'admin', 'password', 'signin', 'auth']
        found = [kw for kw in suspicious_kw if kw in final_domain or kw in final_path]
        if found:
            score -= 15; reasons.append(f'Suspicious keywords in final destination: {", ".join(found)}')

        final_status = final.get('status_code', 0)
        if final_status in [404, 403, 500, 502, 503]:
            score -= 10; reasons.append(f'Final destination returned error status: {final_status}')

        if score >= 75:
            level = 'low'
            if not reasons:
                reasons = ['Safe redirect chain']
        elif score >= 50:
            level = 'medium'
            if not reasons:
                reasons = ['Moderate risk detected']
        else:
            level = 'high'
            if not reasons:
                reasons = ['High-risk redirect pattern detected']

        return {'level': level, 'score': max(0, score), 'reasons': reasons}


# Module-level instance and public function
_analyzer = RedirectChainAnalyzer()


def analyze_redirect_chain(url: str) -> dict:
    """Analyze URL redirect chain with detailed hop info and risk scoring"""
    return _analyzer.analyze(url)
