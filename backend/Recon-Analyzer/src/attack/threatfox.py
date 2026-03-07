import json
import logging
import os

import requests

logger = logging.getLogger(__name__)


def threatfox(query: str):
    """Search ThreatFox for IOC information."""
    auth_key = os.getenv("THREATFOX_API_KEY")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "search_ioc", "search_term": query}
    headers = {
        "Content-Type": "application/json",
    }
    
    if auth_key:
        headers["Auth-Key"] = auth_key

    try:
        logger.info(f"Querying ThreatFox for: {query}")
        response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=15)
        
        if response.status_code != 200:
            logger.error(f"ThreatFox API returned status code {response.status_code}")
            return {"found": False, "error": f"API returned status {response.status_code}"}

        result = response.json()
        data = result.get("data", [])
        
        if data and isinstance(data, list):
            for element in data:
                ioc_id = element.get("id", "")
                logger.info(f"ThreatFox found IOC: {ioc_id}")
                return {
                    "found": True,
                    "id": ioc_id,
                    "ioc": element.get("ioc", ""),
                    "threat_type": element.get("threat_type", ""),
                    "malware": element.get("malware_printable", ""),
                    "confidence_level": element.get("confidence_level", ""),
                    "reference": element.get("reference", ""),
                    "link": f"https://threatfox.abuse.ch/ioc/{ioc_id}" if ioc_id else None
                }
        
        logger.info(f"ThreatFox: No IOC found for {query}")
        return {"found": False}

    except requests.exceptions.Timeout:
        logger.error(f"ThreatFox request timed out for {query}")
        return {"found": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        logger.error(f"ThreatFox API request failed: {e}")
        return {"found": False, "error": str(e)}
    except Exception as e:
        logger.error(f"ThreatFox unexpected error: {e}")
        return {"found": False, "error": str(e)}

