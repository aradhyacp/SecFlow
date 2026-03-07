import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def validate_phone_number(number, country_code=None):
    """
    Validate a phone number using the NumVerify API.
    
    Args:
        number (str): The phone number to validate.
        country_code (str): Optional country code for the phone number.

    Returns:
        dict: The API response in JSON format.
    """
    api_key = os.getenv("NUMVERIFY_API_KEY")
    
    if not api_key:
        logger.warning("NUMVERIFY_API_KEY not configured")
        return {"valid": False, "error": "API key not configured"}

    url = "http://apilayer.net/api/validate"
    params = {
        "access_key": api_key,
        "number": number,
        "country_code": country_code or "",
        "format": 1
    }

    try:
        logger.info(f"Validating phone number: {number}")
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()

        data = response.json()
        
        if not data.get("valid", False):
            logger.info(f"Phone number {number} is not valid")
            return {"valid": False}
        
        logger.info(f"Phone number {number} validated successfully")
        return {
            "valid": True,
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "location": data.get("location"),
            "carrier": data.get("carrier"),
            "line_type": data.get("line_type")
        }
        
    except requests.exceptions.Timeout:
        logger.error(f"NumVerify request timed out for {number}")
        return {"valid": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        logger.error(f"NumVerify API request failed: {e}")
        return {"valid": False, "error": str(e)}
    except Exception as e:
        logger.error(f"NumVerify unexpected error: {e}")
        return {"valid": False, "error": str(e)}


if __name__ == "__main__":
    # Example usage - only runs when executed directly
    result = validate_phone_number("141585862")
    print(result)