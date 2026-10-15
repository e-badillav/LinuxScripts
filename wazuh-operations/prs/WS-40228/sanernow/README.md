# SanerNow-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing SanerNow](#installing-sanernow)
    * [Initial SanerNow Configuration](#initial-sanernow-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

This integration brings patch compliance and remediation data from [SecPod SanerNow](https://www.secpod.com/saner-patch-management/) (patch and vulnerability management, SaaS) into Wazuh.

A Python script running on the Wazuh manager polls the SanerNow REST API, normalizes each record into a common `sanernow` structure and sends it to the Wazuh analysis engine through the `analysisd` Unix socket. The built-in JSON decoder parses the events and custom rules generate alerts for missing patches (with a higher level for high and critical severity) and remediation events.

This lets Wazuh users see patch status next to Wazuh's own vulnerability detection and agent inventory data, and build dashboards for patch compliance reporting.

> **Important:** this is a **reference implementation**. It was built without access to a SanerNow tenant, so the API endpoints (`/patches/missing`, `/patches/remediation`), the authentication header and the response field names are placeholders marked with `TODO` in the script. They must be adjusted to the SanerNow API documentation for your tenant before use. See [Using the Integration Files](#using-the-integration-files).

---

## Compatibility

* Wazuh manager on Linux (on-premises deployments).
* SecPod SanerNow (SaaS) with REST API access.

## Version

* Wazuh 4.x.
* SanerNow REST API: to be confirmed against your tenant's API documentation.

### Prerequisites

* A running Wazuh manager 4.x.
* Python 3 with the `requests` module. The Python interpreter bundled with Wazuh (`/var/ossec/framework/python/bin/python3`) already includes it.
* Outbound HTTPS access (TCP 443) from the Wazuh manager to your SanerNow tenant.
* SanerNow API credentials (API key or OAuth client) with read access to patch and remediation data.
* Root access to the Wazuh manager to edit files under `/var/ossec/`.

---

### Installation and Configuration

#### Installing SanerNow

SanerNow is a SaaS platform, so no installation is required. An existing SanerNow tenant with managed devices is assumed.

#### Initial SanerNow Configuration

1. Sign in to the SanerNow console with an administrator account.
2. Generate API credentials (API key, or client ID and secret if your tenant uses OAuth).
3. Take note of your tenant's API base URL.
4. From the SanerNow API documentation, identify:
    * The endpoint that returns missing patches / patch compliance per device.
    * The endpoint that returns remediation (patch deployment) status, if available.
    * The authentication header format.
    * The pagination parameters and the key that holds the results in the JSON response.

#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed. Refer to the [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

#### Initial Wazuh Configuration (if applicable)

No additional modules are required. Optionally, enable `logall_json` in `/var/ossec/etc/ossec.conf` to verify that events reach the manager during testing (see [Integration Testing](#integration-testing)).

#### Using the Integration Files

This directory contains:

| File | Description |
|---|---|
| `custom-sanernow.py` | Polls the SanerNow API and sends events to Wazuh. |
| `sanernow_rules.xml` | Rules for SanerNow events (IDs `311000`-`311003`). |
| `sample_logs/sanernow_sample_events.json` | Sample events in the format sent by the script (mock data), for testing with `wazuh-logtest`. |

**Python script**

1. Copy the script to the Wazuh manager:

    ```bash
    cp custom-sanernow.py /var/ossec/integrations/custom-sanernow.py
    chmod 750 /var/ossec/integrations/custom-sanernow.py
    chown root:wazuh /var/ossec/integrations/custom-sanernow.py
    ```

2. Edit the configuration section at the top of the script:

    ```python
    API_BASE_URL = "https://your-tenant.sanernow.com/api/v1"
    API_KEY = os.environ.get("SANERNOW_API_KEY", "YOUR_API_KEY_HERE")
    ```

    | Variable | Description |
    |---|---|
    | `API_BASE_URL` | SanerNow API base URL for your tenant. |
    | `API_KEY` | API key. Read from the `SANERNOW_API_KEY` environment variable, or set it in the script. |
    | `LOOKBACK_HOURS` | How far back to look on the first run (default `1`). |
    | `LIMIT` | Maximum results per API call (default `500`). |
    | `TIMEOUT` | HTTP timeout in seconds (default `30`). |
    | `LOG_FILE` | Script log file (default `/var/ossec/logs/integrations.log`). |
    | `STATE_FILE` | Stores the time of the last successful poll (default `/var/ossec/integrations/.sanernow_last_poll`). |

3. Adapt the parts marked with `TODO` to the SanerNow API:
    * `get_headers()`: authentication header (the template uses `Authorization: Bearer <API_KEY>`).
    * `fetch_missing_patches()` and `fetch_remediation_status()`: endpoint paths, query parameters (`updated_since`, `limit`, pagination) and the key that contains the results (`results` in the template).
    * `normalize_event()`: map the SanerNow field names to the `sanernow.*` fields used by the rules.

**Rules**

1. Copy the rules file to the Wazuh manager:

    ```bash
    cp sanernow_rules.xml /var/ossec/etc/rules/sanernow_rules.xml
    chown wazuh:wazuh /var/ossec/etc/rules/sanernow_rules.xml
    chmod 660 /var/ossec/etc/rules/sanernow_rules.xml
    ```

    Custom decoders are not needed: the events are JSON and are parsed by the built-in JSON decoder.

2. Restart the Wazuh manager:

    ```bash
    systemctl restart wazuh-manager
    ```

---

### Integration Steps

**Data flow**

```
SanerNow REST API  --(HTTPS)-->  custom-sanernow.py (Wazuh manager)
        --(analysisd socket, location "sanernow")-->  JSON decoder  -->  sanernow rules  -->  alerts
```

1. On each run, the script reads the time of the last successful poll from the state file. On the first run it looks back `LOOKBACK_HOURS`.
2. It requests missing patches and remediation status updated since that time.
3. Each record is normalized and sent to `/var/ossec/queue/sockets/queue` with this structure:

    ```json
    {"integration":"sanernow","sanernow":{"event_type":"missing_patch","asset_hostname":"...","asset_ip":"...","os":"...","patch_name":"...","patch_id":"...","cve_id":"...","severity":"...","patch_status":"...","published_date":"...","detected_date":"...","category":"..."}}
    ```

    `event_type` is `missing_patch` or `remediation`. In the alerts, the fields appear under `data.sanernow.*`.
4. The current time is saved in the state file for the next run.

**Rules**

| Rule ID | Level | Description |
|---|---|---|
| `311000` | 0 | Base rule for any SanerNow event. |
| `311001` | 5 | Missing patch. |
| `311002` | 10 | Missing patch with high or critical severity. |
| `311003` | 3 | Patch remediation event. |

**Scheduling**

Add the following block to `/var/ossec/etc/ossec.conf` on the manager and restart it:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>sanernow</tag>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-sanernow.py</command>
  <interval>15m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

An interval of 5 to 15 minutes is recommended. Each run sends a burst of events; volumes in the thousands per run are handled by the manager without tuning.

**Storage**

Alerts are stored in the default `wazuh-alerts-*` indices, so no index template changes are needed. A custom index with its own template and ISM policy is only required if patch data needs a different retention than security alerts. See [Creating a custom index pattern](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html#creating-custom-index-pattern).

---

### Integration Testing

**1. Test the rules with `wazuh-logtest`**

Run `/var/ossec/bin/wazuh-logtest` and paste one of the lines from `sample_logs/sanernow_sample_events.json`:

* First line (critical missing patch): should match rule `311002`.
* Second line (medium missing patch): should match rule `311001`.
* Third line (remediation): should match rule `311003`.

**2. Run the script manually**

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-sanernow.py
tail -n 20 /var/ossec/logs/integrations.log
```

Expected log lines:

```
INFO - [sanernow] Starting SanerNow integration run
INFO - [sanernow] Polling for changes since: <timestamp>
INFO - [sanernow] Fetched <N> missing patch records from SanerNow
INFO - [sanernow] Fetched <N> remediation records from SanerNow
INFO - [sanernow] SanerNow integration run completed. Events sent: <N>
```

`HTTP error` or `Connection error` lines point to a wrong URL, endpoint or credentials.

**3. Check that the events reach Wazuh**

Enable `logall_json` inside the `<global>` section of `/var/ossec/etc/ossec.conf`, restart the manager and run:

```bash
tail -f /var/ossec/logs/archives/archives.json | grep sanernow
```

Disable `logall_json` again once the events are confirmed. Alerts can be checked with:

```bash
grep '"sanernow"' /var/ossec/logs/alerts/alerts.json
```

**4. View the alerts in the Wazuh dashboard**

Go to **Threat Hunting** (or **Security events** on older versions) and filter with `rule.groups: sanernow`.

**Correlation with Wazuh Vulnerability Detection**

Wazuh Vulnerability Detection scans agent inventories independently of the event pipeline, so its findings cannot be correlated in real time with SanerNow events through rules, and Wazuh does not deduplicate across the two sources. Both datasets can be compared in dashboards using the hostname, IP and CVE ID fields.

---

### Sources

* [SecPod SanerNow Patch Management](https://www.secpod.com/saner-patch-management/)
* [Wazuh - Command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
* [Wazuh - Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
* [Wazuh - JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
* [Wazuh - wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
* [Wazuh - Vulnerability detection: how it works](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)
* [Wazuh - Indexer indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
