# Kaspersky Cloud-Wazuh Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)
    * [Installing Kaspersky Security Center Cloud Console](#installing-kaspersky-security-center-cloud-console)
    * [Initial Kaspersky Security Center Cloud Console Configuration](#initial-kaspersky-security-center-cloud-console-configuration)
    * [Installing Wazuh (if applicable)](#installing-wazuh-if-applicable)
    * [Initial Wazuh Configuration (if applicable)](#initial-wazuh-configuration-if-applicable)
    * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

### Introduction

This ruleset adds decoders and rules for events exported by Kaspersky Security Center Cloud Console (KSC Cloud) through syslog. It covers:

* **Kaspersky Endpoint Security (KES) events in Spanish**: malware detections and their remediation result, protection components stopped or disabled, outdated databases, group policy and KSN status.
* **Administration Server audit events**: console connections (`has connected to the Administration Server`), both as plain messages and in the structured `[event@23668 ...]` format.

It gives Wazuh users alerts for malware that was not remediated, tampering with endpoint protection and access to the Kaspersky administration console.

---

## Compatibility

* Kaspersky Security Center Cloud Console exporting events through syslog.
* Kaspersky Endpoint Security for Windows, with the event language set to **Spanish**. KES events in other languages are decoded only partially (see [Integration Testing](#integration-testing)).

## Version

* Tested with Wazuh 4.x.
* Tested with Kaspersky Endpoint Security for Windows 12.x (`KES.14.0.0` application folder) and KSC Cloud Console events.

### Prerequisites

* A running Wazuh manager 4.x.
* A Kaspersky Security Center Cloud Console workspace with permissions to configure event export to a SIEM system.
* Network access from KSC Cloud Console to the Wazuh manager on the syslog port (e.g. TCP 514), or to a Wazuh agent or syslog server that forwards the events.

---

### Installation and Configuration

#### Installing Kaspersky Security Center Cloud Console

KSC Cloud Console is a SaaS platform, so no installation is required. An existing workspace with managed devices running Kaspersky Endpoint Security is assumed.

#### Initial Kaspersky Security Center Cloud Console Configuration

1. In KSC Cloud Console, open the settings for exporting events to a SIEM system.
2. Select **syslog** as the format and set the address and port of the Wazuh manager (or the forwarding host).
3. Select the events to export. At least:
    * Malware detection and remediation events (e.g. *Object deleted*, *Cannot be disinfected*, *Backup copy of object created*).
    * Protection component status events (*Task stopped*, *Protection components disabled*).
    * Database status events (*Databases are extremely out of date*).
    * Administration Server audit events (*Connection to the Administration Server*).
4. Save the settings.

Refer to the KSC Cloud Console documentation, section *Exporting events to SIEM systems*, for the detailed steps.

#### Installing Wazuh (if applicable)

A standard Wazuh installation is assumed. Refer to the [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).

#### Initial Wazuh Configuration (if applicable)

Configure the Wazuh manager to receive syslog. Add the following block to `/var/ossec/etc/ossec.conf`, replacing `allowed-ips` with the address the events come from:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>203.0.113.0/24</allowed-ips>
</remote>
```

See [Remote syslog configuration](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html) for other options.

#### Using the Integration Files

This directory contains:

| File | Description |
|---|---|
| `kaspersky_decoders.xml` | Decoders for KSC Cloud events (`kaspersky-cloud`). |
| `kaspersky_rules.xml` | Rules for KSC Cloud events (IDs `100200`-`100210`). |
| `sample_logs/kaspersky_cloud_events.log` | 30 sample events (anonymized) for testing with `wazuh-logtest`. |

**Option 1: command line**

```bash
cp kaspersky_decoders.xml /var/ossec/etc/decoders/kaspersky_decoders.xml
cp kaspersky_rules.xml /var/ossec/etc/rules/kaspersky_rules.xml
chown wazuh:wazuh /var/ossec/etc/decoders/kaspersky_decoders.xml /var/ossec/etc/rules/kaspersky_rules.xml
chmod 660 /var/ossec/etc/decoders/kaspersky_decoders.xml /var/ossec/etc/rules/kaspersky_rules.xml
systemctl restart wazuh-manager
```

**Option 2: Wazuh dashboard**

Go to **Server management > Decoders > Manage decoders files > Import files** and import `kaspersky_decoders.xml`. Then do the same in **Server management > Rules** with `kaspersky_rules.xml`, and restart the manager when prompted.

Files placed in `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/` are loaded automatically, so no changes to `ossec.conf` are needed for them.

---

### Integration Steps

**Data flow**

```
KES endpoints --> KSC Cloud Console --(syslog)--> Wazuh manager --> kaspersky-cloud decoders --> kaspersky_cloud rules --> alerts
```

**Event formats**

All events start with a timestamp, the host and the product/version (`KES|11.0.0.0` or `1093|1.0.0.0`). The parent decoder `kaspersky-cloud` matches on the `<product>|<version>` token.

1. KES events in Spanish. Fields are separated by the literal characters `\r\n` (not real line breaks):

    ```
    2026-09-18T18:38:03.000Z win-endpoint01 KES|11.0.0.0 Tipo de evento: Objeto eliminado\r\nNombre: SearchProtocolHost.exe\r\n...\r\nDescripción del resultado: Eliminado\r\nTipo: Virus\r\nNombre: EICAR-Test-File\r\n...
    ```

2. Administration Server audit events, as plain messages:

    ```
    ... 1093|1.0.0.0 User "test@test.com" has connected to the Administration Server from "0.0.0.0".
    ```

3. Structured events with an `[event@23668 ...]` block:

    ```
    ... 1093|1.0.0.0 - KLAUD_EV_SERVERCONNECT [event@23668 p2="0.0.0.0" ... et="KLAUD_EV_SERVERCONNECT" etdn="Audit (connection to the Administration Server)" hdn="<Administration Server>" hip="127.0.0.1" gn="Managed devices" kscfqdn="..."] User "..." has connected to the Administration Server from "0.0.0.0".
    ```

**Decoded fields**

| Field | Source |
|---|---|
| `kaspersky.event_type` | `Tipo de evento` |
| `kaspersky.process_name`, `kaspersky.process_path`, `kaspersky.pid` | `Nombre`, `Ruta de la aplicación`, `ID del proceso` |
| `kaspersky.result` | `Descripción del resultado` |
| `kaspersky.threat_type`, `kaspersky.threat_name` | `Tipo`, `Nombre` (after `Tipo`) |
| `kaspersky.subject_user` | `Usuario`, or the user in `has connected to the Administration Server` |
| `kaspersky.object`, `kaspersky.object_type`, `kaspersky.object_path`, `kaspersky.object_name` | `Objeto`, `Tipo del objeto`, `Ruta al objeto`, `Nombre del objeto` |
| `kaspersky.reason` | `Razón` / `Motivo` |
| `kaspersky.sha256`, `kaspersky.md5` | `SHA256`, `MD5` |
| `kaspersky.component` | `Componente` |
| `kaspersky.src_ip` | IP in `has connected to the Administration Server from` |
| `kaspersky.event_id`, `kaspersky.event_code`, `kaspersky.event_description` | Event name before `[event@23668`, `et`, `etdn` |
| `kaspersky.admin_server_name`, `kaspersky.admin_server_ip`, `kaspersky.group`, `kaspersky.ksc_fqdn` | `hdn`, `hip`, `gn`, `kscfqdn` |

**Rules**

| Rule ID | Level | Description |
|---|---|---|
| `100200` | 3 | Base rule for any Kaspersky Cloud event. |
| `100201` | 3 | Group policy applied. |
| `100202` | 3 | KSN status reported. |
| `100203` | 7 | Signature databases severely outdated. |
| `100204` | 10 | Protection component stopped. |
| `100205` | 12 | Protection components disabled. |
| `100206` | 7 | Threat detected and neutralized (deleted, backed up or disinfected). |
| `100207` | 12 | Threat detected and **not** remediated. |
| `100208` | 13 | Threat detected by keyword (fallback for result values not covered by `100206`/`100207`). |
| `100210` | 3 | User connected to the Administration Server. |

---

### Integration Testing

**1. Test with `wazuh-logtest`**

Run `/var/ossec/bin/wazuh-logtest` and paste lines from `sample_logs/kaspersky_cloud_events.log`. Expected matches for some of them:

| Sample event | Expected rule |
|---|---|
| `Tipo de evento: No se puede desinfectar` (result `No procesado`) | `100207` |
| `Tipo de evento: Objeto eliminado` (result `Eliminado`) | `100206` |
| `Tipo de evento: Tarea detenida` | `100204` |
| `Tipo de evento: Componentes de protección desactivados` | `100205` |
| `Tipo de evento: Las bases de datos están muy desactualizadas` | `100203` |
| `User "test@test.com" has connected to the Administration Server` | `100210` |

**2. Check that the events reach Wazuh**

Enable `logall_json` inside the `<global>` section of `/var/ossec/etc/ossec.conf`, restart the manager and run:

```bash
tail -f /var/ossec/logs/archives/archives.json | grep -E 'KES\||1093\|'
```

Disable `logall_json` again once the events are confirmed. Alerts can be checked with:

```bash
grep kaspersky /var/ossec/logs/alerts/alerts.json
```

**3. View the alerts in the Wazuh dashboard**

Go to **Threat Hunting** (or **Security events** on older versions) and filter with `rule.groups: kaspersky_cloud`.

**Notes**

* The KES decoders match Spanish field names. If KES events are exported in another language, only the parent decoder and the Administration Server decoders apply; the field regexes must be translated for full coverage.
* Rule `100208` can also fire on events already classified by `100206`/`100207`. If that happens, keep only one of the two approaches, as noted in `kaspersky_rules.xml`.

---

### Sources

* [Wazuh - Custom decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/custom.html)
* [Wazuh - Sibling decoders](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/sibling-decoders.html)
* [Wazuh - Rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
* [Wazuh - Remote syslog](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html)
* [Wazuh - wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
* Kaspersky Security Center Cloud Console Help - *Exporting events to SIEM systems*.
