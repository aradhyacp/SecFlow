"""
Website Carbon Footprint Service
Calculates the carbon emissions and energy usage of a website
"""
import requests
from typing import Dict, Any


def get_carbon_footprint(url: str) -> Dict[str, Any]:
    """
    Calculate website carbon footprint using Website Carbon API
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing carbon footprint statistics
    """
    try:
        # First, get the size of the website's HTML
        response = requests.get(url, timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        response.raise_for_status()
        
        # Calculate size in bytes
        size_in_bytes = len(response.content)
        
        # Use that size to get the carbon data
        api_url = f"https://api.websitecarbon.com/data?bytes={size_in_bytes}&green=0"
        
        carbon_response = requests.get(api_url, timeout=10)
        carbon_response.raise_for_status()
        carbon_data = carbon_response.json()
        
        # Check if there's enough data
        if not carbon_data.get('statistics') or \
           (carbon_data['statistics'].get('adjustedBytes', 0) == 0 and \
            carbon_data['statistics'].get('energy', 0) == 0):
            return {
                "skipped": "Not enough info to get carbon data"
            }
        
        carbon_data['scanUrl'] = url
        return carbon_data
        
    except requests.RequestException as e:
        raise Exception(f"Error fetching carbon data: {str(e)}")
    except Exception as e:
        raise Exception(f"Error processing carbon data: {str(e)}")
