"""
Tranco Ranking Service
Retrieves website ranking from Tranco list (research-oriented ranking list)
"""
import requests
import os
from typing import Dict, Any
from urllib.parse import urlparse


def get_rank(url: str) -> Dict[str, Any]:
    """
    Get domain ranking from Tranco list
    
    Args:
        url: The URL to check ranking for
        
    Returns:
        Dictionary containing ranking information
    """
    try:
        domain = urlparse(url).hostname
        if not domain:
            raise Exception('Invalid URL')
        
        # Get credentials from environment if available
        tranco_username = os.getenv('TRANCO_USERNAME')
        tranco_api_key = os.getenv('TRANCO_API_KEY')
        auth = None
        
        if tranco_username and tranco_api_key:
            auth = (tranco_username, tranco_api_key)
        
        response = requests.get(
            f'https://tranco-list.eu/api/ranks/domain/{domain}',
            auth=auth,
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        
        if not data or not data.get('ranks') or len(data['ranks']) == 0:
            return {
                "skipped": f"Skipping, as {domain} isn't ranked in the top 100 million sites yet."
            }
        
        return data
        
    except Exception as e:
        return {"error": f"Unable to fetch rank, {str(e)}"}
