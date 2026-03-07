"""
URL Parser Service - Structural analysis and suspicious-indicator detection for URLs.
Ported from Url-Analyzer.
"""
import re
import logging
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


class URLParserService:
    """Parse URL into components and flag suspicious patterns"""

    SUSPICIOUS_PROTO_PATTERNS = [
        r'javascript:', r'data:', r'vbscript:', r'about:', r'file://', r'telnet:', r'ftp:',
    ]
    SUSPICIOUS_KEYWORDS = [
        'admin', 'login', 'signin', 'update', 'verify', 'confirm',
        'account', 'password', 'urgent', 'action', 'click'
    ]

    def parse(self, url: str) -> dict:
        """Parse URL and return component breakdown with risk indicators"""
        try:
            if not url.startswith(('http://', 'https://', 'ftp://')):
                url = 'https://' + url

            parsed = urlparse(url)
            result = {
                'original_url': url,
                'is_valid': self._is_valid_url(url),
                'scheme': parsed.scheme,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path or '/',
                'query': parsed.query,
                'fragment': parsed.fragment,
                'username': parsed.username,
                'password': '***' if parsed.password else None,  # Never expose credentials
                'netloc': parsed.netloc,
                'components': self._extract_components(parsed),
                'path_analysis': self._analyze_path(parsed.path),
                'query_analysis': self._analyze_query(parsed.query),
                'suspicious_indicators': self._check_suspicious(url, parsed),
                'risk_level': 'low'
            }

            indicator_count = len(result['suspicious_indicators'])
            result['risk_level'] = 'high' if indicator_count > 2 else ('medium' if indicator_count > 0 else 'low')

            return result

        except Exception as e:
            logger.error(f"Error parsing URL: {str(e)}")
            return {'is_valid': False, 'error': str(e), 'original_url': url}

    def _is_valid_url(self, url: str) -> bool:
        return bool(re.match(r'^https?://[^\s/$.?#].[^\s]*$', url, re.IGNORECASE))

    def _extract_components(self, parsed) -> dict:
        return {
            'subdomain': self._extract_subdomain(parsed.hostname),
            'domain': self._extract_domain(parsed.hostname),
            'tld': self._extract_tld(parsed.hostname),
            'full_hostname': parsed.hostname,
        }

    def _extract_subdomain(self, hostname: str):
        if not hostname:
            return None
        parts = hostname.split('.')
        return '.'.join(parts[:-2]) if len(parts) > 2 else None

    def _extract_domain(self, hostname: str):
        if not hostname:
            return None
        parts = hostname.split('.')
        return parts[-2] if len(parts) >= 2 else (parts[0] if parts else None)

    def _extract_tld(self, hostname: str):
        if not hostname:
            return None
        parts = hostname.split('.')
        return parts[-1] if parts else None

    def _analyze_path(self, path: str) -> dict:
        if not path or path == '/':
            return {'path': path, 'segments': [], 'depth': 0, 'has_file': False,
                    'file_name': None, 'suspicious_segments': []}

        segments = [s for s in path.split('/') if s]
        file_name = None
        has_file = False

        if segments and '.' in segments[-1]:
            file_name = segments[-1]
            has_file = True
            segments = segments[:-1]

        suspicious_segments = [s for s in segments if self._is_suspicious_segment(s)]
        return {
            'path': path, 'segments': segments, 'depth': len(segments),
            'has_file': has_file, 'file_name': file_name,
            'suspicious_segments': suspicious_segments,
            'is_suspicious': len(suspicious_segments) > 0
        }

    def _analyze_query(self, query: str) -> dict:
        if not query:
            return {'query_string': query, 'parameters': [], 'count': 0, 'suspicious_params': []}

        params = []
        suspicious_params = []
        try:
            for key, values in parse_qs(query).items():
                is_suspicious = self._is_suspicious_param(key, values)
                params.append({'key': key, 'values': values, 'is_suspicious': is_suspicious})
                if is_suspicious:
                    suspicious_params.append(key)
        except Exception as e:
            logger.warning(f"Could not parse query string: {str(e)}")

        return {
            'query_string': query, 'parameters': params, 'count': len(params),
            'suspicious_params': suspicious_params,
            'is_suspicious': len(suspicious_params) > 0
        }

    def _is_suspicious_segment(self, segment: str) -> bool:
        return any(kw in segment.lower() for kw in self.SUSPICIOUS_KEYWORDS)

    def _is_suspicious_param(self, key: str, values: list) -> bool:
        suspicious_keys = ['id', 'token', 'session', 'user', 'pass', 'email', 'admin']
        return any(sk in key.lower() for sk in suspicious_keys)

    def _check_suspicious(self, url: str, parsed) -> list:
        suspicious = []

        if parsed.scheme not in ['http', 'https']:
            suspicious.append(f"Unusual protocol: {parsed.scheme}")

        lower_url = url.lower()
        for pattern in self.SUSPICIOUS_PROTO_PATTERNS:
            if re.search(pattern, lower_url):
                suspicious.append(f"Suspicious pattern detected: {pattern}")

        # Credentials embedded in URL
        if parsed.username:
            suspicious.append("Credentials embedded in URL")

        if self._is_obfuscated_ip(parsed.hostname):
            suspicious.append("Obfuscated IP address detected")

        if len(parsed.path) > 255:
            suspicious.append("Extremely long path detected")

        if '\x00' in url:
            suspicious.append("Null byte in URL detected")

        if '%25' in url:
            suspicious.append("Double URL encoding detected")

        return suspicious

    def _is_obfuscated_ip(self, hostname: str) -> bool:
        if not hostname:
            return False
        if hostname.startswith('0x'):
            return True
        parts = hostname.split('.')
        if len(parts) <= 2:
            try:
                if all(part.startswith('0') and len(part) > 1 for part in parts):
                    return True
            except Exception:
                pass
        return False


# Module-level instance and public function
_url_parser = URLParserService()


def parse_url(url: str) -> dict:
    """Parse URL structure and flag suspicious patterns"""
    return _url_parser.parse(url)
