# Okta-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Okta](#installing-okta)
    * [Initial Okta Configuration](#initial-okta-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

This integration collects authentication and administration events from the [Okta System Log API](https://developer.okta.com/docs/reference/api/system-log/) and ingests them into Wazuh.

A Python script running on the Wazuh manager polls the Okta System Log API, wraps each event as `{"okta": <event>}` and sends it directly to the Wazuh analysis engine through the `analysisd` Unix socket. Custom decoders extract the Okta fields and custom rules generate alerts for relevant activity, such as:

* MFA authentications and sign-on policy evaluations.
* OIDC token grants.
* User lifecycle changes (user created, activated, deactivated).
* Password resets.
* Active Directory agent LDAP reads.

This gives Wazuh users visibility of identity events in Okta, correlated with the rest of their security data.

---

## Compatibility

* Wazuh manager on Linux (on-premises deployments).
* Okta Workforce Identity Cloud tenants with access to the System Log API (`/api/v1/logs`).

## Version

* Tested with Wazuh 4.x.
* Okta System Log API v1.

### Prerequisites

* A running Wazuh manager 4.x.
* The Python interpreter bundled with Wazuh (`/var/ossec/framework/python/bin/python3`), which already includes the `requests` module.
* Outbound HTTPS access (TCP 443) from the Wazuh manager to your Okta domain (e.g. `https://yourcompany.okta.com`).
* An Okta API token created by an administrator with read access to the System Log (e.g. Read-only Administrator).
* Root access to the Wazuh manager to edit files under `/var/ossec/`.

---

### Installation and Configuration

#### Installing Okta

Okta is a SaaS platform, so no installation is required. An existing Okta tenant is assumed.

#### Initial Okta Configuration

1. Sign in to the Okta Admin Console as an administrator.
2. Go to **Security > API > Tokens**.
3. Click **Create Token**, give it a name (e.g. `wazuh-integration`) and copy the token value. It is shown only once.
4. Take note of your Okta domain (e.g. `https://yourcompany.okta.com`).

> The token inherits the permissions of the administrator who creates it. Using a dedicated, read-only administrator account is recommended.

See [Create an API token](https://developer.okta.com/docs/guides/create-an-api-token/main/) for details.

#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed. Refer to the [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

#### Initial Wazuh Configuration (if applicable)

No additional modules are required. Optionally, enable `logall_json` in `/var/ossec/etc/ossec.conf` to verify that events reach the manager during testing (see [Integration Testing](#integration-testing)).

#### Using the Integration Files

This directory contains:

| File | Description |
|---|---|
| `scripts/okta_api.py` | Polls the Okta System Log API and sends events to Wazuh. |
| `ruleset/okta_decoders.xml` | Decoders for Okta System Log events. |
| `ruleset/okta_rules.xml` | Rules for Okta events (IDs `310001`-`310009`). |
| `sample_logs/okta_sample_event.json` | Sample event, as sent by the script, for testing with `wazuh-logtest`. |

**Python script**

1. Copy the script to the Wazuh manager:

    ```bash
    cp scripts/okta_api.py /var/ossec/integrations/okta_api.py
    ```

2. Edit the configuration variables at the top of the script:

    ```python
    OKTA_DOMAIN = "https://yourcompany.okta.com"       # Replace with your Okta domain
    API_TOKEN = "YOUR_OKTA_API_TOKEN"                   # Replace with your API token
    ```

3. Set the permissions:

    ```bash
    chmod 750 /var/ossec/integrations/okta_api.py
    chown root:wazuh /var/ossec/integrations/okta_api.py
    ```

**Decoders and rules**

1. Copy the decoders and rules to the Wazuh manager:

    ```bash
    cp ruleset/okta_decoders.xml /var/ossec/etc/decoders/okta_decoders.xml
    cp ruleset/okta_rules.xml /var/ossec/etc/rules/okta_rules.xml
    chown wazuh:wazuh /var/ossec/etc/decoders/okta_decoders.xml /var/ossec/etc/rules/okta_rules.xml
    chmod 660 /var/ossec/etc/decoders/okta_decoders.xml /var/ossec/etc/rules/okta_rules.xml
    ```

    Files placed in `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/` are loaded automatically, so no changes to `ossec.conf` are needed for them.

2. Restart the Wazuh manager:

    ```bash
    systemctl restart wazuh-manager
    ```

---

### Integration Steps

**Data flow**

```
Okta System Log API  --(HTTPS, SSWS token)-->  okta_api.py (Wazuh manager)
        --(analysisd socket, location "okta")-->  okta decoders  -->  okta rules  -->  alerts
```

1. On each run, the script reads the timestamp of the last processed event from `/var/ossec/integrations/.okta_state`. On the first run it fetches the last 10 minutes (`INITIAL_LOOKBACK_MINUTES`).
2. It queries `/api/v1/logs` in ascending order, following the `Link: rel="next"` header to paginate.
3. If Okta returns HTTP `429`, it waits until `X-Rate-Limit-Reset` (or uses exponential backoff) and retries, up to 5 times.
4. Each event is sent to `/var/ossec/queue/sockets/queue` as `{"okta": <event>}`.
5. The timestamp of the last event is written back to the state file.

**Scheduling**

The script must run periodically. Use **one** of the following options.

*Option A - Wazuh `command` wodle (recommended)*

Add the following block to `/var/ossec/etc/ossec.conf` on the manager and restart it:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>okta</tag>
  <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/okta_api.py</command>
  <interval>5m</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```

*Option B - cron*

Edit the root crontab with `crontab -e` and add:

```
*/5 * * * * /var/ossec/framework/python/bin/python3 /var/ossec/integrations/okta_api.py
```

---

### Integration Testing

**1. Test the decoders and rules with `wazuh-logtest`**

Run `/var/ossec/bin/wazuh-logtest` and paste the content of `sample_logs/okta_sample_event.json`. The event should match rule `310003`:

```
**Phase 3: Completed filtering (rules).
        id: '310003'
        level: '5'
        description: 'User authentication via MFA for John Doe (jdoe@example.com) - Result: SUCCESS'
        groups: '['okta']'
        firedtimes: '1'
        mail: 'False'
**Alert to be generated.
```

**2. Run the script manually**

```bash
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/okta_api.py
```

Expected output:

```
[INFO] Fetched and sent <N> Okta events.
```

Generate activity in Okta (e.g. sign in with MFA, create a test user or reset a password) and run the script again.

**3. Check that the events reach Wazuh**

Enable `logall_json` inside the `<global>` section of `/var/ossec/etc/ossec.conf`, restart the manager and run:

```bash
tail -f /var/ossec/logs/archives/archives.json | grep okta
```

Disable `logall_json` again once the events are confirmed.

Generated alerts can be checked with:

```bash
grep '"okta"' /var/ossec/logs/alerts/alerts.json
```

**4. View the alerts in the Wazuh dashboard**

Go to **Threat Hunting** (or **Security events** on older versions) and filter with `rule.groups: okta`.

**Troubleshooting**

* Errors from the script are written to `stderr`. When running from the wodle, check `/var/ossec/logs/ossec.log`.
* `401` responses mean that the API token or domain is incorrect.
* To re-fetch events from scratch, delete `/var/ossec/integrations/.okta_state`.

---

### Sources

* [Okta System Log API](https://developer.okta.com/docs/reference/api/system-log/)
* [Okta - Create an API token](https://developer.okta.com/docs/guides/create-an-api-token/main/)
* [Okta - Rate limits](https://developer.okta.com/docs/reference/rl-global-mgmt/)
* [Wazuh - Command wodle](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html)
* [Wazuh - Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
* [Wazuh - Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
* [Wazuh - wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
