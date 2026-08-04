#!/var/ossec/framework/python/bin/python3
# =============================================================================
# custom-threatdown.py
# Wazuh Custom Integration — ThreatDown (Malwarebytes Nebula) API
# =============================================================================
# Description:
#   Polls the ThreatDown Nebula API for detections and suspicious activity,
#   then injects events into the Wazuh analysis engine via the UNIX socket.
#
# Deployment:
#   /var/ossec/integrations/custom-threatdown.py
#   Permissions: 750, Owner: root:wazuh
#
# Scheduling:
#   Configured via <wodle name="command"> in ossec.conf
#
# Based on patterns from:
#   - Wazuh CrowdStrike Integration (WG00051)
#   - Wazuh Integration Guide (TKB)
#   - ThreatDown Nebula API documentation
# =============================================================================

import datetime
import fcntl
import hashlib
import json
import logging
import os
import sys
import time
from socket import AF_UNIX, SOCK_DGRAM, socket

try:
    import requests
except ImportError:
    print("ERROR: 'requests' module not found. Install with:")
    print("  /var/ossec/framework/python/bin/python3 -m pip install requests")
    sys.exit(1)


# =============================================================================
# CONFIGURATION — Update these values before deployment
# =============================================================================

# ThreatDown API credentials (OAuth2 client_credentials)
# Generate at: Nebula Console -> Integrate -> OAuth2 Clients
CLIENT_ID     = os.environ.get("THREATDOWN_CLIENT_ID", "YOUR_CLIENT_ID")
CLIENT_SECRET = os.environ.get("THREATDOWN_CLIENT_SECRET", "YOUR_CLIENT_SECRET")

# Nebula Account ID (UUID from the console URL)
# Example: If your console URL is https://cloud.malwarebytes.com/nebula/123e4567-e89b-...
# Then ACCOUNT_ID = "123e4567-e89b-..."
ACCOUNT_ID    = os.environ.get("THREATDOWN_ACCOUNT_ID", "YOUR_ACCOUNT_ID")

# API variant: "nebula" or "oneview"
API_VARIANT   = os.environ.get("THREATDOWN_API_VARIANT", "nebula")

# Base URL
API_BASE_URL  = "https://api.malwarebytes.com"

# Token endpoints
TOKEN_ENDPOINTS = {
    "nebula":  f"{API_BASE_URL}/oauth2/token",
    "oneview": f"{API_BASE_URL}/oneview/oauth2/token",
}

# How far back to look on the first run (hours)
INITIAL_LOOKBACK_HOURS = 24

# Maximum events per API page
PAGE_SIZE = 500

# Wazuh UNIX socket for event injection
SOCKET_ADDR   = "/var/ossec/queue/sockets/queue"
MAX_MSG_SIZE  = 65535

# Integration label (used in Wazuh event location and rules)
LABEL = "threatdown"

# State and log files
STATE_FILE = "/var/ossec/var/run/custom-threatdown-state.json"
LOCK_FILE  = "/var/ossec/var/run/custom-threatdown.lock"
LOG_FILE   = "/var/ossec/logs/integrations.log"

# HTTP timeout (seconds)
HTTP_TIMEOUT = 30

# HTTP retry settings (for transient network errors / 5xx responses)
MAX_RETRIES        = 3
RETRY_BACKOFF_BASE  = 2  # seconds; doubles each attempt

# Overlap window applied when advancing the polling checkpoint, to absorb
# ingestion latency on the ThreatDown side. Without this, an event that
# becomes queryable a few minutes late can fall permanently between two
# polling windows. Cross-run duplicates caused by the overlap are removed
# by the seen_ids dedup below.
POLL_OVERLAP_MINUTES = 10

# Maximum number of event IDs to retain for deduplication across runs
MAX_SEEN_IDS = 10000

# Endpoints to poll (set to False to disable)
POLL_DETECTIONS         = True
POLL_SUSPICIOUS_ACTIVITY = True
POLL_QUARANTINE          = True

# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [custom-threatdown] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("custom-threatdown")


# =============================================================================
# EXECUTION LOCK
# =============================================================================

_lock_fd = None


def acquire_lock():
    """
    Prevent overlapping runs (e.g. a slow API response causing the next
    wodle-scheduled execution to start before this one finishes), which
    would otherwise race on state.json and double-send events.
    Returns True if the lock was acquired, False if another run is active.
    """
    global _lock_fd
    _lock_fd = open(LOCK_FILE, "w")
    try:
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        _lock_fd.close()
        _lock_fd = None
        return False


# =============================================================================
# STATE MANAGEMENT (Deduplication)
# =============================================================================

def load_state():
    """Load the last-run state from disk."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("Failed to load state file, starting fresh: %s", e)
    return {}


def save_state(state):
    """Atomically save state to disk."""
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, STATE_FILE)
    except IOError as e:
        logger.error("Failed to save state: %s", e)


# =============================================================================
# HTTP SESSION / RETRY
# =============================================================================

SESSION = requests.Session()


def request_with_retry(method, url, **kwargs):
    """
    Perform an HTTP request with retries on transient failures
    (connection errors, timeouts, and 5xx responses). 4xx responses are
    not retried since they indicate a request/config problem, not a
    transient issue.
    """
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = SESSION.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
            if resp.status_code >= 500 and attempt < MAX_RETRIES:
                logger.warning("Attempt %d/%d: %s returned %d, retrying",
                                attempt, MAX_RETRIES, url, resp.status_code)
                time.sleep(RETRY_BACKOFF_BASE * attempt)
                continue
            return resp
        except requests.exceptions.RequestException as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                logger.warning("Attempt %d/%d: request to %s failed (%s), retrying",
                                attempt, MAX_RETRIES, url, e)
                time.sleep(RETRY_BACKOFF_BASE * attempt)
    raise last_exc


# =============================================================================
# AUTHENTICATION
# =============================================================================

def get_access_token():
    """Obtain an OAuth2 access token using client_credentials grant."""
    token_url = TOKEN_ENDPOINTS.get(API_VARIANT, TOKEN_ENDPOINTS["nebula"])

    try:
        response = request_with_retry(
            "POST",
            token_url,
            auth=(CLIENT_ID, CLIENT_SECRET),
            data={
                "grant_type": "client_credentials",
                "scope": "read"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            logger.error("Token response missing 'access_token': %s", token_data)
            return None
        logger.info("Successfully obtained access token (expires in %ss)",
                     token_data.get("expires_in", "unknown"))
        return access_token

    except requests.exceptions.RequestException as e:
        logger.error("Authentication failed: %s", e)
        return None


def build_headers(token):
    """Build request headers with auth token."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # Nebula API requires the accountid header
    if API_VARIANT == "nebula" and ACCOUNT_ID:
        headers["accountid"] = ACCOUNT_ID
    return headers


# =============================================================================
# WAZUH EVENT INJECTION
# =============================================================================

def send_event_to_wazuh(event, event_type="detection"):
    """
    Send an event to the Wazuh analysis engine via the UNIX socket.

    Format: "1:<location>:<json_payload>"
    Where <location> identifies the source for decoder matching.
    """
    try:
        wazuh_event = {
            "integration": "custom-threatdown",
            "threatdown": {
                "event_type": event_type,
                **event
            }
        }
        json_msg = json.dumps(wazuh_event, default=str, separators=(",", ":"))
        payload = f"1:{LABEL}:{json_msg}"
        encoded = payload.encode()

        if len(encoded) > MAX_MSG_SIZE:
            logger.warning("Event exceeds max size (%d > %d), truncating data fields",
                           len(encoded), MAX_MSG_SIZE)
            # Remove large fields to fit
            for key in ["full_log", "raw_data", "details"]:
                if key in wazuh_event.get("threatdown", {}):
                    del wazuh_event["threatdown"][key]
            json_msg = json.dumps(wazuh_event, default=str, separators=(",", ":"))
            payload = f"1:{LABEL}:{json_msg}"
            encoded = payload.encode()

            if len(encoded) > MAX_MSG_SIZE:
                logger.error("Event still exceeds max size (%d > %d) after truncation, "
                             "dropping event_id=%s", len(encoded), MAX_MSG_SIZE,
                             compute_event_id(event, event_type))
                return

        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(SOCKET_ADDR)
            sock.send(encoded)

    except Exception as e:
        logger.error("Failed to send event to Wazuh: %s", e)


# =============================================================================
# API POLLING — DETECTIONS
# =============================================================================

def fetch_detections(token, since_date):
    """
    Fetch detections from ThreatDown Nebula/OneView API.
    Uses cursor-based pagination.
    """
    if API_VARIANT == "oneview":
        url = f"{API_BASE_URL}/oneview/v1/detections"
    else:
        url = f"{API_BASE_URL}/nebula/v1/detections"

    headers = build_headers(token)
    all_detections = []
    next_cursor = ""

    while True:
        body = {
            "next_cursor": next_cursor,
            "page_size": PAGE_SIZE,
            "start_date": since_date,
        }

        try:
            resp = request_with_retry("POST", url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            logger.error("Detections API request failed: %s", e)
            break
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in detections response: %s", e)
            break

        detections = data.get("detections", data.get("results", []))
        if not isinstance(detections, list):
            logger.warning("Unexpected detections format: %s", type(detections))
            break

        all_detections.extend(detections)
        next_cursor = data.get("next_cursor", "")

        if not next_cursor:
            break

        logger.info("Fetching next page of detections (cursor: %s...)", next_cursor[:20])

    logger.info("Retrieved %d detections since %s", len(all_detections), since_date)
    return all_detections


# =============================================================================
# API POLLING — SUSPICIOUS ACTIVITY (EDR)
# =============================================================================

def fetch_suspicious_activity(token, since_date):
    """
    Fetch suspicious activity events from ThreatDown EDR.
    Available only with EDR license.
    """
    if API_VARIANT == "oneview":
        # OneView requires site-specific endpoint
        logger.info("Suspicious Activity for OneView requires per-site polling (not implemented)")
        return []

    url = f"{API_BASE_URL}/nebula/v1/sa"
    headers = build_headers(token)
    params = {
        "page_size": PAGE_SIZE,
        "start": since_date,
    }

    all_events = []
    try:
        resp = request_with_retry("GET", url, headers=headers, params=params)
        if resp.status_code == 404:
            logger.info("Suspicious Activity endpoint not available (EDR license may be required)")
            return []
        resp.raise_for_status()
        data = resp.json()
        events = data.get("suspicious_activities", data.get("results", []))
        if isinstance(events, list):
            all_events.extend(events)
    except requests.exceptions.RequestException as e:
        logger.error("Suspicious Activity API request failed: %s", e)

    logger.info("Retrieved %d suspicious activity events since %s", len(all_events), since_date)
    return all_events


# =============================================================================
# API POLLING — QUARANTINE
# =============================================================================

def fetch_quarantine(token, since_date):
    """
    Fetch quarantined threats from ThreatDown.
    """
    if API_VARIANT == "oneview":
        logger.info("Quarantine for OneView requires per-site polling (not implemented)")
        return []

    url = f"{API_BASE_URL}/nebula/v1/quarantine"
    headers = build_headers(token)
    params = {
        "page_size": PAGE_SIZE,
        "since": since_date,
    }

    all_items = []
    try:
        resp = request_with_retry("GET", url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("quarantine", data.get("results", []))
        if isinstance(items, list):
            all_items.extend(items)
    except requests.exceptions.RequestException as e:
        logger.error("Quarantine API request failed: %s", e)

    logger.info("Retrieved %d quarantine items since %s", len(all_items), since_date)
    return all_items


# =============================================================================
# EVENT DEDUPLICATION
# =============================================================================

def compute_event_id(event, event_type):
    """
    Compute a unique hash for deduplication.
    Uses the source ID if available, otherwise hashes key fields.

    The event_type is included in the id because detections, suspicious
    activity, and quarantine come from independent ID spaces — without
    the prefix, a coincidental ID collision across categories would make
    one of the two events look like a duplicate and get silently dropped.
    """
    # Try direct ID fields
    event_id = event.get("id") or event.get("detection_id") or event.get("event_id")
    if event_id:
        return f"{event_type}:{event_id}"

    # Fallback: hash key fields
    unique_payload = {
        "threat_name": event.get("threat_name", event.get("category", "")),
        "path": event.get("path", ""),
        "machine": event.get("machine", {}).get("id", "") if isinstance(event.get("machine"), dict) else "",
        "scanned_at": event.get("scanned_at", event.get("reported_at", "")),
    }
    raw = json.dumps(unique_payload, sort_keys=True)
    return f"{event_type}:{hashlib.sha256(raw.encode()).hexdigest()[:16]}"


def filter_new_events(events, event_type, seen_ids):
    """Filter out events we've already processed."""
    new_events = []
    for event in events:
        eid = compute_event_id(event, event_type)
        if eid not in seen_ids:
            seen_ids[eid] = True
            new_events.append(event)
    return new_events


# =============================================================================
# MAIN
# =============================================================================

def main():
    logger.info("=" * 60)
    logger.info("Starting ThreatDown integration (variant=%s)", API_VARIANT)

    if not acquire_lock():
        logger.warning("Another instance is already running. Exiting.")
        sys.exit(0)

    # Validate configuration
    if CLIENT_ID == "YOUR_CLIENT_ID" or CLIENT_SECRET == "YOUR_CLIENT_SECRET":
        logger.error("CLIENT_ID and CLIENT_SECRET must be configured. Exiting.")
        sys.exit(1)

    if API_VARIANT == "nebula" and ACCOUNT_ID == "YOUR_ACCOUNT_ID":
        logger.error("ACCOUNT_ID must be configured for Nebula variant. Exiting.")
        sys.exit(1)

    # Load state. seen_ids is a dict used as an insertion-ordered set: it
    # needs both fast membership checks and a stable oldest-to-newest order
    # so trimming below discards the oldest IDs rather than an arbitrary
    # subset (a plain set() has no reliable order to trim by).
    state = load_state()
    seen_ids = dict.fromkeys(state.get("seen_ids", []), True)

    # Determine the start date
    last_run = state.get("last_run_timestamp")
    if last_run:
        since_date = last_run
        logger.info("Resuming from last run: %s", since_date)
    else:
        since_dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=INITIAL_LOOKBACK_HOURS)
        since_date = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        logger.info("First run — looking back %d hours to %s", INITIAL_LOOKBACK_HOURS, since_date)

    # Authenticate
    token = get_access_token()
    if not token:
        logger.error("Cannot proceed without a valid token. Exiting.")
        sys.exit(1)

    total_sent = 0

    # --- Poll Detections ---
    if POLL_DETECTIONS:
        try:
            detections = fetch_detections(token, since_date)
            new_detections = filter_new_events(detections, "detection", seen_ids)
            logger.info("New detections to send: %d (of %d total)", len(new_detections), len(detections))
            for det in new_detections:
                send_event_to_wazuh(det, event_type="detection")
                total_sent += 1
        except Exception as e:
            logger.error("Error processing detections: %s", e)

    # --- Poll Suspicious Activity ---
    if POLL_SUSPICIOUS_ACTIVITY:
        try:
            sa_events = fetch_suspicious_activity(token, since_date)
            new_sa = filter_new_events(sa_events, "suspicious_activity", seen_ids)
            logger.info("New suspicious activity events to send: %d (of %d total)", len(new_sa), len(sa_events))
            for sa in new_sa:
                send_event_to_wazuh(sa, event_type="suspicious_activity")
                total_sent += 1
        except Exception as e:
            logger.error("Error processing suspicious activity: %s", e)

    # --- Poll Quarantine ---
    if POLL_QUARANTINE:
        try:
            q_items = fetch_quarantine(token, since_date)
            new_q = filter_new_events(q_items, "quarantine", seen_ids)
            logger.info("New quarantine items to send: %d (of %d total)", len(new_q), len(q_items))
            for q in new_q:
                send_event_to_wazuh(q, event_type="quarantine")
                total_sent += 1
        except Exception as e:
            logger.error("Error processing quarantine: %s", e)

    # --- Update state ---
    # Step the checkpoint back by POLL_OVERLAP_MINUTES so the next run's
    # window overlaps this one; seen_ids (namespaced per event_type above)
    # absorbs the resulting re-fetches as duplicates instead of silently
    # losing events that ThreatDown indexed a few minutes late.
    checkpoint = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(minutes=POLL_OVERLAP_MINUTES))
    now = checkpoint.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Keep only the most recently seen IDs to prevent unbounded growth.
    # seen_ids preserves insertion order, so this reliably drops the
    # oldest entries rather than an arbitrary subset.
    if len(seen_ids) > MAX_SEEN_IDS:
        seen_ids = dict.fromkeys(list(seen_ids)[-MAX_SEEN_IDS:], True)

    state["last_run_timestamp"] = now
    state["seen_ids"] = list(seen_ids)
    state["last_run_events_sent"] = total_sent
    save_state(state)

    logger.info("Integration complete. Sent %d events to Wazuh.", total_sent)
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
