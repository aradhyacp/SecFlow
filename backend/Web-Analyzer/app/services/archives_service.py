"""
Wayback Machine Archives Service
Retrieves historical snapshot data from the Internet Archive's Wayback Machine
"""
import requests
from datetime import datetime
from typing import Dict, Any, List


def convert_timestamp_to_date(timestamp: str) -> str:
    """Convert Wayback Machine timestamp to ISO date string"""
    try:
        year = int(timestamp[0:4])
        month = int(timestamp[4:6])
        day = int(timestamp[6:8])
        hour = int(timestamp[8:10])
        minute = int(timestamp[10:12])
        second = int(timestamp[12:14])
        
        dt = datetime(year, month, day, hour, minute, second)
        return dt.isoformat()
    except (ValueError, IndexError):
        return timestamp


def count_page_changes(results: List[List[str]]) -> int:
    """Count the number of times the page content changed based on digest"""
    prev_digest = None
    changes = -1
    
    for result in results:
        if len(result) >= 3 and result[2] != prev_digest:
            prev_digest = result[2]
            changes += 1
    
    return changes


def get_average_page_size(scans: List[List[str]]) -> int:
    """Calculate average page size across all scans"""
    if not scans:
        return 0
    
    total_size = 0
    count = 0
    
    for scan in scans:
        if len(scan) >= 4:
            try:
                size = int(scan[3])
                total_size += size
                count += 1
            except ValueError:
                continue
    
    return round(total_size / count) if count > 0 else 0


def get_scan_frequency(first_scan: str, last_scan: str, total_scans: int, change_count: int) -> Dict[str, float]:
    """Calculate scan frequency statistics"""
    try:
        first_dt = datetime.fromisoformat(first_scan)
        last_dt = datetime.fromisoformat(last_scan)
        
        day_factor = (last_dt - first_dt).total_seconds() / (60 * 60 * 24)
        
        if day_factor == 0:
            day_factor = 1
        
        days_between_scans = round(day_factor / total_scans, 2) if total_scans > 0 else 0
        days_between_changes = round(day_factor / change_count, 2) if change_count > 0 else 0
        scans_per_day = round((total_scans - 1) / day_factor, 2) if day_factor > 0 else 0
        changes_per_day = round(change_count / day_factor, 2) if day_factor > 0 else 0
        
        return {
            "daysBetweenScans": days_between_scans,
            "daysBetweenChanges": days_between_changes,
            "scansPerDay": scans_per_day,
            "changesPerDay": changes_per_day
        }
    except Exception:
        return {
            "daysBetweenScans": 0,
            "daysBetweenChanges": 0,
            "scansPerDay": 0,
            "changesPerDay": 0
        }


def get_archives(url: str) -> Dict[str, Any]:
    """
    Retrieve historical archive data from Wayback Machine
    
    Args:
        url: The URL to check for archives
        
    Returns:
        Dictionary containing archive statistics and scan data
    """
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,statuscode,digest,length,offset"
    
    try:
        response = requests.get(cdx_url, timeout=20)
        response.raise_for_status()
        data = response.json()
        
        # Check if there's data
        if not data or not isinstance(data, list) or len(data) <= 1:
            return {
                "skipped": "Site has never before been archived via the Wayback Machine"
            }
        
        # Remove the header row
        data.pop(0)
        
        # Process and return the results
        first_scan = convert_timestamp_to_date(data[0][0])
        last_scan = convert_timestamp_to_date(data[-1][0])
        total_scans = len(data)
        change_count = count_page_changes(data)
        
        return {
            "firstScan": first_scan,
            "lastScan": last_scan,
            "totalScans": total_scans,
            "changeCount": change_count,
            "averagePageSize": get_average_page_size(data),
            "scanFrequency": get_scan_frequency(first_scan, last_scan, total_scans, change_count),
            "scans": data,
            "scanUrl": url
        }
        
    except requests.RequestException as e:
        raise Exception(f"Error fetching Wayback data: {str(e)}")
    except Exception as e:
        raise Exception(f"Error processing Wayback data: {str(e)}")
