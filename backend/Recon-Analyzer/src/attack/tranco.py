import logging

import requests

logger = logging.getLogger(__name__)


def tranco(query: str):
    """Check domain ranking in the Tranco list."""
    url = f"https://tranco-list.eu/api/ranks/domain/{query}"

    try:
        logger.info(f"Checking Tranco ranking for: {query}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        response_data = response.json()

        if response_data.get("ranks"):
            latest_rank = response_data["ranks"][0]["rank"]
            logger.info(f"Tranco rank for {query}: {latest_rank}")
            return {"found": True, "rank": latest_rank}
        else:
            logger.info(f"Domain {query} not found in Tranco list")
            return {"found": False}

    except requests.exceptions.Timeout:
        logger.error(f"Tranco request timed out for {query}")
        return {"found": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        logger.error(f"Tranco API request failed: {e}")
        return {"found": False, "error": str(e)}
    except Exception as e:
        logger.error(f"Tranco unexpected error: {e}")
        return {"found": False, "error": str(e)}


if __name__ == "__main__":
    print(tranco("wolfram.com"))