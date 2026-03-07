import os
import requests
import re
import logging

logger = logging.getLogger(__name__)

# Get the directory where this script is located
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
database_location = os.path.join(_SCRIPT_DIR, "..", "media", "tor.txt")

def tor(query: str):
    """Check if an IP is a known Tor exit node."""
    try:
        result = {"is_tor_exit": False}
        
        if not os.path.isfile(database_location):
            logger.info("Tor database not found, downloading...")
            if not update():
                return {"is_tor_exit": False, "error": "Failed to download Tor database"}

        with open(database_location, "r", encoding="utf-8") as f:
            db = f.read()

        db_list = [ip.strip() for ip in db.split("\n") if ip.strip()]
        if query in db_list:
            result["is_tor_exit"] = True

        return result
    except Exception as e:
        logger.error(f"Error checking Tor database: {e}")
        return {"is_tor_exit": False, "error": str(e)}

def update():
    """Download the latest Tor exit node list."""
    try:
        logger.info("Starting download of Tor exit nodes")
        url = "https://check.torproject.org/exit-addresses"
        r = requests.get(url, timeout=30)
        r.raise_for_status()

        data_extracted = r.content.decode()
        findings = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", data_extracted)
        
        # Remove duplicates
        unique_ips = list(set(findings))

        # Ensure the directory exists
        os.makedirs(os.path.dirname(database_location), exist_ok=True)

        with open(database_location, "w", encoding="utf-8") as f:
            for ip in unique_ips:
                if ip:
                    f.write(f"{ip}\n")

        logger.info(f"Finished downloading Tor database ({len(unique_ips)} exit nodes)")
        return True
    except Exception as e:
        logger.error(f"Failed to update Tor database: {e}")
        return False


if __name__ == "__main__":
    # Configure logging for standalone testing
    logging.basicConfig(level=logging.INFO)
    print(tor("198.98.51.189"))