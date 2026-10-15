#!/var/ossec/framework/python/bin/python3
"""
Okta System Log -> Wazuh integration.

Fetches events from the Okta System Log API and sends them to Wazuh
via the analysisd Unix socket.

Features:
- State file to track last fetched event (no duplicates, no gaps)
- Pagination support for high-volume tenants
- Rate limit handling with exponential backoff
"""
import json
import os
import sys
import time
import requests
from datetime import datetime, timedelta, timezone
from socket import socket, AF_UNIX, SOCK_DGRAM

# ─── CONFIGURATION ───────────────────────────────────────────────────────────
OKTA_DOMAIN = "https://yourcompany.okta.com"       # Replace with your Okta domain
API_TOKEN = "YOUR_OKTA_API_TOKEN"                   # Replace with your API token
SOCKET_PATH = "/var/ossec/queue/sockets/queue"
STATE_FILE = "/var/ossec/integrations/.okta_state"
LOG_TAG = "okta"
INITIAL_LOOKBACK_MINUTES = 10  # On first run, fetch last N minutes
# ─────────────────────────────────────────────────────────────────────────────

HEADERS = {
    "Authorization": f"SSWS {API_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}


def read_state():
    """Read the last fetched timestamp from the state file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r") as f:
            return f.read().strip()
    return None


def write_state(timestamp):
    """Persist the timestamp of the last fetched event."""
    with open(STATE_FILE, "w") as f:
        f.write(timestamp)


def send_event(event):
    """Send a single event to the Wazuh analysisd socket."""
    try:
        payload = json.dumps({"okta": event})
        message = f"1:{LOG_TAG}:{payload}"
        s = socket(AF_UNIX, SOCK_DGRAM)
        s.connect(SOCKET_PATH)
        s.send(message.encode())
        s.close()
    except Exception as e:
        print(f"[ERROR] Socket send failed: {e}", file=sys.stderr)


def fetch_okta_logs():
    """Fetch logs from Okta System Log API with pagination and state tracking."""
    since = read_state()
    if not since:
        since = (datetime.now(timezone.utc) - timedelta(minutes=INITIAL_LOOKBACK_MINUTES)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    url = f"{OKTA_DOMAIN}/api/v1/logs?since={since}&sortOrder=ASCENDING&limit=100"
    last_published = None
    total_events = 0
    retry_count = 0
    max_retries = 5

    while url:
        try:
            response = requests.get(url, headers=HEADERS, timeout=30)

            if response.status_code == 429:
                retry_count += 1
                if retry_count > max_retries:
                    print("[ERROR] Max retries exceeded.", file=sys.stderr)
                    break
                rate_limit_reset = response.headers.get("X-Rate-Limit-Reset")
                if rate_limit_reset:
                    wait_seconds = max(int(rate_limit_reset) - int(time.time()) + 2, 1)
                else:
                    wait_seconds = 2 ** retry_count
                print(f"[WARN] Rate limited. Waiting {wait_seconds}s...", file=sys.stderr)
                time.sleep(wait_seconds)
                continue

            if response.status_code != 200:
                print(f"[ERROR] Okta API returned {response.status_code}: {response.text}", file=sys.stderr)
                break

            retry_count = 0
            events = response.json()
            for event in events:
                send_event(event)
                total_events += 1
                if "published" in event:
                    last_published = event["published"]

            # Follow pagination via Link header
            url = None
            link_header = response.headers.get("Link", "")
            if 'rel="next"' in link_header:
                for part in link_header.split(","):
                    if 'rel="next"' in part:
                        url = part.split(";")[0].strip().strip("<>")
                        break

            # Small delay between pages to avoid rate limits
            if url:
                time.sleep(0.5)

        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}", file=sys.stderr)
            break

    # Update state with the last event's timestamp
    if last_published:
        write_state(last_published)

    print(f"[INFO] Fetched and sent {total_events} Okta events.", file=sys.stderr)


if __name__ == "__main__":
    fetch_okta_logs()
