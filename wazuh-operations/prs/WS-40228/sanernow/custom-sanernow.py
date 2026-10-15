#!/usr/bin/env python3
"""
SanerNow Patch Management Integration for Wazuh
Polls the SanerNow REST API for patch compliance data
and sends events to the Wazuh analysis queue.

Place this script at: /var/ossec/integrations/custom-sanernow.py
Schedule via: <wodle name="command"> in ossec.conf
"""

import datetime
import json
import logging
import os
import sys
import requests
from socket import AF_UNIX, SOCK_DGRAM, socket

# =============================================================================
# CONFIGURATION — Update these values with your SanerNow API credentials
# =============================================================================

# SanerNow API base URL (update with your tenant URL)
API_BASE_URL = "https://your-tenant.sanernow.com/api/v1"

# Authentication — adjust based on SanerNow's auth method
# Option A: API Key
API_KEY = os.environ.get("SANERNOW_API_KEY", "YOUR_API_KEY_HERE")

# Option B: OAuth (uncomment if applicable)
# CLIENT_ID = os.environ.get("SANERNOW_CLIENT_ID", "xxxxx")
# CLIENT_SECRET = os.environ.get("SANERNOW_CLIENT_SECRET", "xxxxx")

# Wazuh configuration
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
LOG_FILE = "/var/ossec/logs/integrations.log"
LABEL = "sanernow"

# Polling configuration
LOOKBACK_HOURS = 1  # How far back to look for new/updated findings
LIMIT = 500         # Max results per API call (adjust per API docs)
TIMEOUT = 30        # HTTP request timeout in seconds

# =============================================================================
# LOGGING SETUP
# =============================================================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(name)s] %(message)s"
)
logger = logging.getLogger("sanernow")

# =============================================================================
# STATE FILE — Tracks last successful poll to avoid duplicates
# =============================================================================

STATE_FILE = "/var/ossec/integrations/.sanernow_last_poll"


def get_last_poll_time():
    """Read the last successful poll timestamp from state file."""
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                timestamp = f.read().strip()
                return timestamp
    except Exception as e:
        logger.warning("Could not read state file: %s", e)

    # Default: look back LOOKBACK_HOURS
    fallback = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=LOOKBACK_HOURS)
    return fallback.strftime("%Y-%m-%dT%H:%M:%SZ")


def save_last_poll_time():
    """Save current UTC timestamp as last poll time."""
    try:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with open(STATE_FILE, "w") as f:
            f.write(now)
    except Exception as e:
        logger.error("Could not save state file: %s", e)


# =============================================================================
# API INTERACTION
# =============================================================================

def get_headers():
    """Build request headers for SanerNow API."""
    return {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def fetch_missing_patches(since):
    """
    Fetch missing patches / patch compliance data from SanerNow.

    NOTE: Update the endpoint, parameters, and response parsing
    based on the actual SanerNow API documentation.
    """
    # =========================================================================
    # TODO: Replace this endpoint with the actual SanerNow API endpoint
    # Examples might include:
    #   /patches/missing
    #   /assets/compliance
    #   /vulnerabilities/unpatched
    # =========================================================================
    endpoint = f"{API_BASE_URL}/patches/missing"

    params = {
        "updated_since": since,
        "limit": LIMIT,
        # "page": 1,  # Add pagination if supported
    }

    try:
        response = requests.get(
            endpoint,
            headers=get_headers(),
            params=params,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        # =====================================================================
        # TODO: Adjust the key below based on actual API response structure
        # e.g., data["results"], data["patches"], data["data"], etc.
        # =====================================================================
        results = data.get("results", [])
        logger.info("Fetched %d missing patch records from SanerNow", len(results))
        return results

    except requests.exceptions.HTTPError as e:
        logger.error("HTTP error from SanerNow API: %s - %s", e, response.text)
    except requests.exceptions.ConnectionError as e:
        logger.error("Connection error to SanerNow API: %s", e)
    except requests.exceptions.Timeout:
        logger.error("Request to SanerNow API timed out after %ds", TIMEOUT)
    except Exception as e:
        logger.error("Unexpected error fetching from SanerNow: %s", e)

    return []


def fetch_remediation_status(since):
    """
    Fetch remediation/deployment status from SanerNow.

    NOTE: This is a second optional endpoint — include if SanerNow
    provides separate remediation tracking.
    """
    endpoint = f"{API_BASE_URL}/patches/remediation"

    params = {
        "updated_since": since,
        "limit": LIMIT,
    }

    try:
        response = requests.get(
            endpoint,
            headers=get_headers(),
            params=params,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        results = data.get("results", [])
        logger.info("Fetched %d remediation records from SanerNow", len(results))
        return results

    except Exception as e:
        logger.error("Error fetching remediation status: %s", e)
        return []


# =============================================================================
# WAZUH EVENT DELIVERY
# =============================================================================

def send_event_to_wazuh(event, event_type="missing_patch"):
    """
    Send a single event to the Wazuh analysis queue via Unix socket.

    The event is wrapped in a JSON structure with a consistent label
    so that Wazuh decoders can identify and parse it.
    """
    wazuh_event = json.dumps({
        "integration": "sanernow",
        "sanernow": {
            "event_type": event_type,
            **normalize_event(event)
        }
    })

    payload = f"1:{LABEL}:{wazuh_event}"

    try:
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_ADDR)
            sock.send(payload.encode())
    except Exception as e:
        logger.error("Failed to send event to Wazuh socket: %s", e)


def normalize_event(event):
    """
    Normalize the API response fields into a consistent structure.

    TODO: Map SanerNow's actual field names to your desired schema.
    The fields below are examples — adjust based on the real API response.
    """
    return {
        "asset_hostname": event.get("hostname", event.get("device_name", "unknown")),
        "asset_ip": event.get("ip_address", ""),
        "os": event.get("operating_system", ""),
        "patch_name": event.get("patch_name", event.get("title", "")),
        "patch_id": event.get("patch_id", event.get("kb_id", "")),
        "cve_id": event.get("cve_id", event.get("cve", "")),
        "severity": event.get("severity", "unknown"),
        "patch_status": event.get("status", "missing"),
        "published_date": event.get("published_date", ""),
        "detected_date": event.get("detected_date", ""),
        "category": event.get("category", ""),
    }


# =============================================================================
# MAIN EXECUTION
# =============================================================================

def main():
    logger.info("=" * 60)
    logger.info("Starting SanerNow integration run")

    # Get the last poll timestamp
    since = get_last_poll_time()
    logger.info("Polling for changes since: %s", since)

    events_sent = 0

    # Fetch missing patches
    missing_patches = fetch_missing_patches(since)
    for patch in missing_patches:
        send_event_to_wazuh(patch, event_type="missing_patch")
        events_sent += 1

    # Fetch remediation status (optional — remove if not needed)
    remediations = fetch_remediation_status(since)
    for remediation in remediations:
        send_event_to_wazuh(remediation, event_type="remediation")
        events_sent += 1

    # Save state only if successful
    if events_sent > 0 or (not missing_patches and not remediations):
        save_last_poll_time()

    logger.info("SanerNow integration run completed. Events sent: %d", events_sent)
    logger.info("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical("Unhandled exception in SanerNow integration: %s", e)
        sys.exit(1)
