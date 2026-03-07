"""
Website Features Service
Retrieves detailed website features and technologies using BuiltWith API
"""
import requests
import os
from typing import Dict, Any
from urllib.parse import quote


def get_features(url: str) -> Dict[str, Any]:
    """
    Get website features using BuiltWith API
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary containing website features and technologies
    """
    api_key = os.getenv('BUILT_WITH_API_KEY')
    
    if not url:
        raise Exception('URL query parameter is required')
    
    if not api_key:
        raise Exception('Missing BuiltWith API key in environment variables')
    
    try:
        api_url = f"https://api.builtwith.com/free1/api.json?KEY={api_key}&LOOKUP={quote(url)}"
        
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        
        return response.json()
        
    except Exception as e:
        raise Exception(f"Error making request: {str(e)}")
