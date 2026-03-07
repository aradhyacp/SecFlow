"""
Screenshot Service
Captures website screenshot using Selenium WebDriver
"""
import os
import base64
from typing import Dict, Any
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager


def get_screenshot(url: str) -> Dict[str, Any]:
    """
    Capture website screenshot using Selenium
    
    Args:
        url: The URL to capture
        
    Returns:
        Dictionary containing base64 encoded screenshot
    """
    if not url:
        raise Exception('URL is missing from parameters')
    
    # Ensure URL has protocol
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    # Validate URL
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError
    except Exception:
        raise Exception('URL provided is invalid')
    
    driver = None
    try:
        # Configure Chrome options
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        # Use custom Chrome path if provided
        chrome_path = os.getenv('CHROME_PATH')
        if chrome_path:
            chrome_options.binary_location = chrome_path
        
        # Initialize driver with auto-managed ChromeDriver
        try:
            driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=chrome_options
            )
        except Exception as e:
            # Fallback to manual path if webdriver-manager fails
            chromedriver_path = os.getenv('CHROMEDRIVER_PATH', '/usr/bin/chromedriver')
            service = Service(chromedriver_path)
            driver = webdriver.Chrome(service=service, options=chrome_options)
        
        # Set timeouts
        driver.set_page_load_timeout(15)
        driver.implicitly_wait(5)
        
        # Navigate to URL
        driver.get(url)
        
        # Wait for body element to be present
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )
        
        # Take screenshot
        screenshot_bytes = driver.get_screenshot_as_png()
        
        # Convert to base64
        base64_screenshot = base64.b64encode(screenshot_bytes).decode('utf-8')
        
        return {"image": base64_screenshot}
        
    except Exception as e:
        raise Exception(f"Screenshot failed: {str(e)}")
        
    finally:
        if driver:
            driver.quit()
