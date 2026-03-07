"""
API Routes - All web analysis endpoints
"""
from flask import Blueprint, request, jsonify
import logging
from app.utils.middleware import normalize_url, api_handler
from app import check_rate_limit
from app.services import (
    status_service,
    dns_service,
    ssl_service,
    headers_service,
    tech_stack_service,
    whois_service,
    robots_txt_service,
    sitemap_service,
    cookies_service,
    hsts_service,
    security_headers_service,
    security_txt_service,
    redirects_service,
    ports_service,
    get_ip_service,
    social_tags_service,
    txt_records_service,
    linked_pages_service,
    trace_route_service,
    mail_config_service,
    dnssec_service,
    firewall_service,
    dns_server_service,
    tls_service,
    archives_service,
    carbon_service,
    rank_service,
    features_service,
    block_lists_service,
    screenshot_service
)

logger = logging.getLogger(__name__)

bp = Blueprint('api', __name__, url_prefix='/api/web-analyzer')


def get_url_param():
    """Extract and validate URL parameter from request"""
    url = request.args.get('url')
    if not url:
        raise ValueError('URL query parameter is required')
    return normalize_url(url)


@bp.route('/status', methods=['GET'])
@check_rate_limit
@api_handler
def status():
    """Check if website is up"""
    url = get_url_param()
    return status_service.check_status(url)


@bp.route('/dns', methods=['GET'])
@check_rate_limit
@api_handler
def dns():
    """Get DNS records"""
    url = get_url_param()
    return dns_service.get_dns_records(url)


@bp.route('/ssl', methods=['GET'])
@check_rate_limit
@api_handler
def ssl():
    """Get SSL certificate information"""
    url = get_url_param()
    return ssl_service.get_ssl_certificate(url)


@bp.route('/headers', methods=['GET'])
@check_rate_limit
@api_handler
def headers():
    """Get HTTP headers"""
    url = get_url_param()
    return headers_service.get_headers(url)


@bp.route('/tech-stack', methods=['GET'])
@check_rate_limit
@api_handler
def tech_stack():
    """Detect technologies used on website"""
    url = get_url_param()
    return tech_stack_service.detect_tech_stack(url)


@bp.route('/whois', methods=['GET'])
@check_rate_limit
@api_handler
def whois():
    """Get WHOIS information"""
    url = get_url_param()
    return whois_service.get_whois_data(url)


@bp.route('/robots-txt', methods=['GET'])
@check_rate_limit
@api_handler
def robots_txt():
    """Get robots.txt file"""
    url = get_url_param()
    return robots_txt_service.get_robots_txt(url)


@bp.route('/sitemap', methods=['GET'])
@check_rate_limit
@api_handler
def sitemap():
    """Get sitemap.xml entries"""
    url = get_url_param()
    return sitemap_service.get_sitemap(url)


@bp.route('/hsts', methods=['GET'])
@check_rate_limit
@api_handler
def hsts():
    """Check HSTS policy"""
    url = get_url_param()
    return hsts_service.get_hsts_policy(url)


@bp.route('/security-headers', methods=['GET'])
@check_rate_limit
@api_handler
def security_headers():
    """Check security-related headers"""
    url = get_url_param()
    return security_headers_service.check_security_headers(url)


@bp.route('/security-txt', methods=['GET'])
@check_rate_limit
@api_handler
def security_txt():
    """Get security.txt file"""
    url = get_url_param()
    return security_txt_service.get_security_txt(url)


@bp.route('/cookies', methods=['GET'])
@check_rate_limit
@api_handler
def cookies():
    """Get cookies"""
    url = get_url_param()
    return cookies_service.get_cookies(url)


@bp.route('/redirects', methods=['GET'])
@check_rate_limit
@api_handler
def redirects():
    """Trace URL redirects"""
    url = get_url_param()
    return redirects_service.get_redirects(url)


@bp.route('/ports', methods=['GET'])
@check_rate_limit
@api_handler
def ports():
    """Scan open ports"""
    url = get_url_param()
    return ports_service.scan_ports(url)


@bp.route('/get-ip', methods=['GET'])
@check_rate_limit
@api_handler
def get_ip():
    """Get IP address"""
    url = get_url_param()
    return get_ip_service.get_ip(url)


@bp.route('/social-tags', methods=['GET'])
@check_rate_limit
@api_handler
def social_tags():
    """Get social media meta tags"""
    url = get_url_param()
    return social_tags_service.get_social_tags(url)


@bp.route('/txt-records', methods=['GET'])
@check_rate_limit
@api_handler
def txt_records():
    """Get TXT DNS records"""
    url = get_url_param()
    return txt_records_service.get_txt_records(url)


@bp.route('/linked-pages', methods=['GET'])
@check_rate_limit
@api_handler
def linked_pages():
    """Get linked pages"""
    url = get_url_param()
    return linked_pages_service.get_linked_pages(url)


@bp.route('/trace-route', methods=['GET'])
@check_rate_limit
@api_handler
def trace_route():
    """Trace network route"""
    url = get_url_param()
    return trace_route_service.trace_route(url)


@bp.route('/mail-config', methods=['GET'])
@check_rate_limit
@api_handler
def mail_config():
    """Get mail configuration"""
    url = get_url_param()
    return mail_config_service.get_mail_config(url)


@bp.route('/dnssec', methods=['GET'])
@check_rate_limit
@api_handler
def dnssec():
    """Check DNSSEC"""
    url = get_url_param()
    return dnssec_service.check_dnssec(url)


@bp.route('/firewall', methods=['GET'])
@check_rate_limit
@api_handler
def firewall():
    """Detect firewall/WAF"""
    url = get_url_param()
    return firewall_service.detect_firewall(url)


@bp.route('/dns-server', methods=['GET'])
@check_rate_limit
@api_handler
def dns_server():
    """Check DNS server"""
    url = get_url_param()
    return dns_server_service.check_dns_server(url)


@bp.route('/tls', methods=['GET'])
@check_rate_limit
@api_handler
def tls():
    """Check TLS configuration"""
    url = get_url_param()
    return tls_service.check_tls(url)


@bp.route('/archives', methods=['GET'])
@check_rate_limit
@api_handler
def archives():
    """Get Wayback Machine archives"""
    url = get_url_param()
    return archives_service.get_archives(url)


@bp.route('/carbon', methods=['GET'])
@check_rate_limit
@api_handler
def carbon():
    """Get website carbon footprint"""
    url = get_url_param()
    return carbon_service.get_carbon_footprint(url)


@bp.route('/rank', methods=['GET'])
@check_rate_limit
@api_handler
def rank():
    """Get Tranco ranking"""
    url = get_url_param()
    return rank_service.get_rank(url)


@bp.route('/features', methods=['GET'])
@check_rate_limit
@api_handler
def features():
    """Get website features via BuiltWith"""
    url = get_url_param()
    return features_service.get_features(url)


@bp.route('/block-lists', methods=['GET'])
@check_rate_limit
@api_handler
def block_lists():
    """Check DNS blocklists"""
    url = get_url_param()
    return block_lists_service.get_block_lists(url)


@bp.route('/screenshot', methods=['GET'])
@check_rate_limit
@api_handler
def screenshot():
    """Get website screenshot"""
    url = get_url_param()
    return screenshot_service.get_screenshot(url)


@bp.route('/', methods=['GET'])
def api_index():
    """API index - list all endpoints"""
    endpoints = {
        'status': '/api/web-analyzer/status?url=example.com',
        'dns': '/api/web-analyzer/dns?url=example.com',
        'ssl': '/api/web-analyzer/ssl?url=example.com',
        'headers': '/api/web-analyzer/headers?url=example.com',
        'tech-stack': '/api/web-analyzer/tech-stack?url=example.com',
        'whois': '/api/web-analyzer/whois?url=example.com',
        'robots-txt': '/api/web-analyzer/robots-txt?url=example.com',
        'sitemap': '/api/web-analyzer/sitemap?url=example.com',
        'cookies': '/api/web-analyzer/cookies?url=example.com',
        'hsts': '/api/web-analyzer/hsts?url=example.com',
        'security-headers': '/api/web-analyzer/security-headers?url=example.com',
        'security-txt': '/api/web-analyzer/security-txt?url=example.com',
        'redirects': '/api/web-analyzer/redirects?url=example.com',
        'ports': '/api/web-analyzer/ports?url=example.com',
        'get-ip': '/api/web-analyzer/get-ip?url=example.com',
        'social-tags': '/api/web-analyzer/social-tags?url=example.com',
        'txt-records': '/api/web-analyzer/txt-records?url=example.com',
        'linked-pages': '/api/web-analyzer/linked-pages?url=example.com',
        'trace-route': '/api/web-analyzer/trace-route?url=example.com',
        'mail-config': '/api/web-analyzer/mail-config?url=example.com',
        'dnssec': '/api/web-analyzer/dnssec?url=example.com',
        'firewall': '/api/web-analyzer/firewall?url=example.com',
        'dns-server': '/api/web-analyzer/dns-server?url=example.com',
        'tls': '/api/web-analyzer/tls?url=example.com',
        'archives': '/api/web-analyzer/archives?url=example.com',
        'carbon': '/api/web-analyzer/carbon?url=example.com',
        'rank': '/api/web-analyzer/rank?url=example.com',
        'features': '/api/web-analyzer/features?url=example.com',
        'block-lists': '/api/web-analyzer/block-lists?url=example.com',
        'screenshot': '/api/web-analyzer/screenshot?url=example.com',
        'batch': '/api/web-analyzer/batch?url=example.com',
    }
    
    return jsonify({
        'name': 'Web-Analyzer API',
        'version': '1.0.0',
        'endpoints': endpoints,
        'description': 'Flask-based Web URL Analyzer API',
        'usage': 'Append ?url=example.com to any endpoint to analyze a website'
    })


@bp.route('/batch', methods=['GET', 'POST'])
@check_rate_limit
def batch_analysis():
    """Analyze website with all endpoints at once"""
    if request.method == 'POST':
        data = request.get_json()
        url = data.get('url') if data else None
    else:
        url = request.args.get('url')
    
    if not url:
        return jsonify({'error': 'URL parameter is required'}), 400
    
    url = normalize_url(url)
    results = {}
    
    # Define endpoints to check
    checks = {
        'status': status_service.check_status,
        'dns': dns_service.get_dns_records,
        'ssl': ssl_service.get_ssl_certificate,
        'headers': headers_service.get_headers,
        'tech-stack': tech_stack_service.detect_tech_stack,
        'whois': whois_service.get_whois_data,
        'robots-txt': robots_txt_service.get_robots_txt,
        'sitemap': sitemap_service.get_sitemap,
        'cookies': cookies_service.get_cookies,
        'hsts': hsts_service.get_hsts_policy,
        'security-headers': security_headers_service.get_security_headers,
        'security-txt': security_txt_service.get_security_txt,
        'redirects': redirects_service.get_redirects,
        'get-ip': get_ip_service.get_ip,
        'social-tags': social_tags_service.get_social_tags,
        'txt-records': txt_records_service.get_txt_records,
        'linked-pages': linked_pages_service.get_linked_pages,
        'mail-config': mail_config_service.get_mail_config,
        'dnssec': dnssec_service.check_dnssec,
        'firewall': firewall_service.detect_firewall,
        'dns-server': dns_server_service.check_dns_server,
        'tls': tls_service.check_tls,
        'archives': archives_service.get_archives,
        'carbon': carbon_service.get_carbon_footprint,
        'rank': rank_service.get_rank,
        'features': features_service.get_features,
        'block-lists': block_lists_service.get_block_lists,
        'screenshot': screenshot_service.get_screenshot,
    }
    
    # Execute all checks
    for name, func in checks.items():
        try:
            results[name] = func(url)
        except Exception as e:
            results[name] = {'error': str(e)}
    
    return jsonify(results)


@bp.errorhandler(400)
def bad_request(error):
    """Handle 400 errors"""
    return jsonify({'error': 'Bad request'}), 400


@bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f'API error: {error}')
    return jsonify({'error': 'Internal server error'}), 500
