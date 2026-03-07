"""
API Test Client - Mimics frontend calls to backend
Makes actual HTTP requests to test all endpoints
"""

import requests
import json
import logging
from datetime import datetime
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('temp/response.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Configuration
BASE_URL = "http://127.0.0.1:5000/api"
TEST_URL = "instagram.com"
TIMEOUT = 30  # seconds

# All endpoints to test (excluding batch)
ENDPOINTS = [
    'status',
    'dns',
    'ssl',
    'headers',
    'tech-stack',
    'whois',
    'robots-txt',
    'sitemap',
    'cookies',
    'hsts',
    'security-headers',
    'security-txt',
    'redirects',
    'ports',
    'get-ip',
    'social-tags',
    'txt-records',
    'linked-pages',
    'trace-route',
    'mail-config',
    'dnssec',
    'firewall',
    'dns-server',
    'tls',
    'archives',
    'carbon',
    'rank',
    'features',
    'block-lists',
    'screenshot',
]


def log_separator():
    """Log a separator line"""
    logger.info("=" * 80)


def test_endpoint(endpoint_name):
    """
    Test a single endpoint and log the response
    
    Args:
        endpoint_name: Name of the endpoint to test
    """
    url = f"{BASE_URL}/{endpoint_name}"
    params = {"url": TEST_URL}
    
    log_separator()
    logger.info(f"Testing endpoint: {endpoint_name}")
    logger.info(f"Request URL: {url}?url={TEST_URL}")
    
    try:
        start_time = datetime.now()
        response = requests.get(url, params=params, timeout=TIMEOUT, verify=False)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        logger.info(f"Status Code: {response.status_code}")
        logger.info(f"Response Time: {duration:.2f}s")
        logger.info(f"Response Headers: {dict(response.headers)}")
        
        # Try to parse JSON response
        try:
            response_data = response.json()
            logger.info(f"Response Body:")
            logger.info(json.dumps(response_data, indent=2, default=str))
            
            # Check for errors in response
            if isinstance(response_data, dict) and 'error' in response_data:
                logger.warning(f"⚠️  Endpoint returned error: {response_data['error']}")
            elif response.status_code == 200:
                logger.info(f"✓ Endpoint successful")
            else:
                logger.warning(f"⚠️  Non-200 status code")
                
        except json.JSONDecodeError:
            logger.warning(f"⚠️  Response is not valid JSON")
            logger.info(f"Raw Response: {response.text[:500]}")
            
    except requests.exceptions.Timeout:
        logger.error(f"✗ Timeout after {TIMEOUT}s")
    except requests.exceptions.ConnectionError:
        logger.error(f"✗ Connection error - is the server running?")
    except requests.exceptions.RequestException as e:
        logger.error(f"✗ Request failed: {str(e)}")
    except Exception as e:
        logger.error(f"✗ Unexpected error: {str(e)}")
    
    logger.info("")  # Empty line for readability


def test_all_endpoints():
    """Test all endpoints sequentially"""
    log_separator()
    logger.info(f"Starting API Test Suite")
    logger.info(f"Base URL: {BASE_URL}")
    logger.info(f"Test URL: {TEST_URL}")
    logger.info(f"Total Endpoints: {len(ENDPOINTS)}")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    log_separator()
    logger.info("")
    
    successful = 0
    failed = 0
    errors = 0
    
    for endpoint in ENDPOINTS:
        try:
            test_endpoint(endpoint)
            successful += 1
        except Exception as e:
            logger.error(f"Critical error testing {endpoint}: {str(e)}")
            errors += 1
    
    # Summary
    log_separator()
    logger.info("TEST SUMMARY")
    log_separator()
    logger.info(f"Total Endpoints Tested: {len(ENDPOINTS)}")
    logger.info(f"Successful: {successful}")
    logger.info(f"Failed: {failed}")
    logger.info(f"Errors: {errors}")
    logger.info(f"Completion Time: {datetime.now().isoformat()}")
    log_separator()


def test_server_availability():
    """Check if the server is running"""
    try:
        logger.info("Checking server availability...")
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code == 200:
            logger.info("✓ Server is running and responding")
            data = response.json()
            logger.info(f"API Name: {data.get('name')}")
            logger.info(f"API Version: {data.get('version')}")
            logger.info(f"Total Endpoints: {len(data.get('endpoints', {}))}")
            return True
        else:
            logger.error(f"✗ Server returned status code: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        logger.error("✗ Cannot connect to server - is it running?")
        logger.error(f"   Expected server at: {BASE_URL}")
        return False
    except Exception as e:
        logger.error(f"✗ Error checking server: {str(e)}")
        return False


if __name__ == "__main__":
    print("\n" + "="*80)
    print("API Test Client - Frontend Request Simulator")
    print("="*80 + "\n")
    
    # Check server availability first
    if not test_server_availability():
        logger.error("\nPlease start the server first:")
        logger.error("cd /home/sunaykulkarni/IntelX/backend/Web-Analyzer")
        logger.error("python run.py")
        exit(1)
    
    print("\nStarting endpoint tests...\n")
    
    # Test all endpoints
    test_all_endpoints()
    
    print("\n" + "="*80)
    print("Testing Complete - Check temp/response.log for detailed results")
    print("="*80 + "\n")
