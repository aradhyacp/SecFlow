"""
Test suite for Web-Analyzer API endpoints
Run with: python -m pytest tests.py
"""

import sys
import os
import warnings
import urllib3

# Suppress warnings
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
import json

# Test data
TEST_URL = "https://facebook.com"

def test_client():
    """Create test client"""
    return app.test_client()

def test_api_index():
    """Test API index endpoint"""
    client = test_client()
    response = client.get('/api/')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'name' in data
    assert 'endpoints' in data
    print("✓ API Index test passed")

def test_status_endpoint():
    """Test status endpoint"""
    client = test_client()
    response = client.get(f'/api/status?url={TEST_URL}')
    
    print(f"Status endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Status endpoint test completed")

def test_dns_endpoint():
    """Test DNS endpoint"""
    client = test_client()
    response = client.get(f'/api/dns?url={TEST_URL}')
    
    print(f"DNS endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ DNS endpoint test completed")

def test_headers_endpoint():
    """Test headers endpoint"""
    client = test_client()
    response = client.get(f'/api/headers?url={TEST_URL}')
    
    print(f"Headers endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Found {len(data)} headers")
    print("✓ Headers endpoint test completed")

def test_ssl_endpoint():
    """Test SSL endpoint"""
    client = test_client()
    response = client.get(f'/api/ssl?url={TEST_URL}')
    
    print(f"SSL endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"SSL Data keys: {list(data.keys()) if isinstance(data, dict) else type(data)}")
    print("✓ SSL endpoint test completed")

def test_robots_txt_endpoint():
    """Test robots.txt endpoint"""
    client = test_client()
    response = client.get(f'/api/robots-txt?url={TEST_URL}')
    
    print(f"Robots.txt endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Robots.txt endpoint test completed")

def test_whois_endpoint():
    """Test WHOIS endpoint"""
    client = test_client()
    response = client.get(f'/api/whois?url={TEST_URL}')
    
    print(f"WHOIS endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ WHOIS endpoint test completed")

def test_get_ip_endpoint():
    """Test get IP endpoint"""
    client = test_client()
    response = client.get(f'/api/get-ip?url={TEST_URL}')
    
    print(f"Get IP endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Get IP endpoint test completed")

def test_hsts_endpoint():
    """Test HSTS endpoint"""
    client = test_client()
    response = client.get(f'/api/hsts?url={TEST_URL}')
    
    print(f"HSTS endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ HSTS endpoint test completed")

def test_tech_stack_endpoint():
    """Test tech stack endpoint"""
    client = test_client()
    response = client.get(f'/api/tech-stack?url={TEST_URL}')
    
    print(f"Tech stack endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Tech stack endpoint test completed")

def test_security_headers_endpoint():
    """Test security headers endpoint"""
    client = test_client()
    response = client.get(f'/api/security-headers?url={TEST_URL}')
    
    print(f"Security headers endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Security headers endpoint test completed")

def test_cookies_endpoint():
    """Test cookies endpoint"""
    client = test_client()
    response = client.get(f'/api/cookies?url={TEST_URL}')
    
    print(f"Cookies endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Cookies endpoint test completed")

def test_sitemap_endpoint():
    """Test sitemap endpoint"""
    client = test_client()
    response = client.get(f'/api/sitemap?url={TEST_URL}')
    
    print(f"Sitemap endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys()) if isinstance(data, dict) else 'list'}")
    print("✓ Sitemap endpoint test completed")

def test_security_txt_endpoint():
    """Test security.txt endpoint"""
    client = test_client()
    response = client.get(f'/api/security-txt?url={TEST_URL}')
    
    print(f"Security.txt endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Security.txt endpoint test completed")

def test_redirects_endpoint():
    """Test redirects endpoint"""
    client = test_client()
    response = client.get(f'/api/redirects?url={TEST_URL}')
    
    print(f"Redirects endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Redirects endpoint test completed")

def test_ports_endpoint():
    """Test ports endpoint"""
    client = test_client()
    response = client.get(f'/api/ports?url={TEST_URL}')
    
    print(f"Ports endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Ports endpoint test completed")

def test_social_tags_endpoint():
    """Test social tags endpoint"""
    client = test_client()
    response = client.get(f'/api/social-tags?url={TEST_URL}')
    
    print(f"Social tags endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Social tags endpoint test completed")

def test_txt_records_endpoint():
    """Test TXT records endpoint"""
    client = test_client()
    response = client.get(f'/api/txt-records?url={TEST_URL}')
    
    print(f"TXT records endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ TXT records endpoint test completed")

def test_linked_pages_endpoint():
    """Test linked pages endpoint"""
    client = test_client()
    response = client.get(f'/api/linked-pages?url={TEST_URL}')
    
    print(f"Linked pages endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys()) if isinstance(data, dict) else 'list'}")
    print("✓ Linked pages endpoint test completed")

def test_trace_route_endpoint():
    """Test trace route endpoint"""
    client = test_client()
    response = client.get(f'/api/trace-route?url={TEST_URL}')
    
    print(f"Trace route endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys()) if isinstance(data, dict) else 'list'}")
    print("✓ Trace route endpoint test completed")

def test_mail_config_endpoint():
    """Test mail config endpoint"""
    client = test_client()
    response = client.get(f'/api/mail-config?url={TEST_URL}')
    
    print(f"Mail config endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Mail config endpoint test completed")

def test_dnssec_endpoint():
    """Test DNSSEC endpoint"""
    client = test_client()
    response = client.get(f'/api/dnssec?url={TEST_URL}')
    
    print(f"DNSSEC endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ DNSSEC endpoint test completed")

def test_firewall_endpoint():
    """Test firewall endpoint"""
    client = test_client()
    response = client.get(f'/api/firewall?url={TEST_URL}')
    
    print(f"Firewall endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Firewall endpoint test completed")

def test_dns_server_endpoint():
    """Test DNS server endpoint"""
    client = test_client()
    response = client.get(f'/api/dns-server?url={TEST_URL}')
    
    print(f"DNS server endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ DNS server endpoint test completed")

def test_tls_endpoint():
    """Test TLS endpoint"""
    client = test_client()
    response = client.get(f'/api/tls?url={TEST_URL}')
    
    print(f"TLS endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ TLS endpoint test completed")

def test_archives_endpoint():
    """Test archives endpoint"""
    client = test_client()
    response = client.get(f'/api/archives?url={TEST_URL}')
    
    print(f"Archives endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Archives endpoint test completed")

def test_carbon_endpoint():
    """Test carbon endpoint"""
    client = test_client()
    response = client.get(f'/api/carbon?url={TEST_URL}')
    
    print(f"Carbon endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Carbon endpoint test completed")

def test_rank_endpoint():
    """Test rank endpoint"""
    client = test_client()
    response = client.get(f'/api/rank?url={TEST_URL}')
    
    print(f"Rank endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Rank endpoint test completed")

def test_features_endpoint():
    """Test features endpoint"""
    client = test_client()
    response = client.get(f'/api/features?url={TEST_URL}')
    
    print(f"Features endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Features endpoint test completed")

def test_block_lists_endpoint():
    """Test block lists endpoint"""
    client = test_client()
    response = client.get(f'/api/block-lists?url={TEST_URL}')
    
    print(f"Block lists endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Block lists endpoint test completed")

def test_screenshot_endpoint():
    """Test screenshot endpoint"""
    client = test_client()
    response = client.get(f'/api/screenshot?url={TEST_URL}')
    
    print(f"Screenshot endpoint response: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.data)
        print(f"Data keys: {list(data.keys())}")
    print("✓ Screenshot endpoint test completed")

def test_missing_url_parameter():
    """Test missing URL parameter"""
    client = test_client()
    response = client.get('/api/status')
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    print("✓ Missing URL parameter test passed")

# def test_batch_endpoint():
#     """Test batch analysis endpoint"""
#     client = test_client()
#     response = client.get(f'/api/batch?url={TEST_URL}')
    
#     print(f"Batch endpoint response: {response.status_code}")
#     if response.status_code == 200:
#         data = json.loads(response.data)
#         print(f"Batch results keys: {list(data.keys())}")
#     print("✓ Batch endpoint test completed")

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*50)
    print("Web-Analyzer API Tests")
    print("="*50 + "\n")
    
    tests = [
        test_api_index,
        test_missing_url_parameter,
        test_status_endpoint,
        test_dns_endpoint,
        test_headers_endpoint,
        test_ssl_endpoint,
        test_robots_txt_endpoint,
        test_whois_endpoint,
        test_get_ip_endpoint,
        test_hsts_endpoint,
        test_tech_stack_endpoint,
        test_security_headers_endpoint,
        test_cookies_endpoint,
        test_sitemap_endpoint,
        test_security_txt_endpoint,
        test_redirects_endpoint,
        test_ports_endpoint,
        test_social_tags_endpoint,
        test_txt_records_endpoint,
        test_linked_pages_endpoint,
        test_trace_route_endpoint,
        test_mail_config_endpoint,
        test_dnssec_endpoint,
        test_firewall_endpoint,
        test_dns_server_endpoint,
        test_tls_endpoint,
        test_archives_endpoint,
        test_carbon_endpoint,
        test_rank_endpoint,
        test_features_endpoint,
        test_block_lists_endpoint,
        test_screenshot_endpoint,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            print(f"\nRunning: {test.__name__}")
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__} failed: {str(e)}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__} error: {str(e)}")
            failed += 1
    
    print("\n" + "="*50)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*50 + "\n")

if __name__ == '__main__':
    run_all_tests()
