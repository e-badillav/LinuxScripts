## Description

Adds a reference integration for SecPod SanerNow (patch and vulnerability management, SaaS) that polls the SanerNow REST API and sends patch compliance and remediation data to Wazuh.

Related ticket: WS-40228

> This is a reference implementation. The SanerNow API endpoints, authentication header and field names are placeholders (marked with `TODO`) and must be adjusted to the tenant's API documentation. This is stated in the README.

## Changes

New directory `integrations/integrations/sanernow/`:

- `custom-sanernow.py`: polls the SanerNow API for missing patches and remediation status and sends each record to the Wazuh `analysisd` socket as `{"integration":"sanernow","sanernow":{...}}`.
  - State file with the time of the last successful poll.
  - Normalizes records into common `sanernow.*` fields (hostname, IP, OS, patch, CVE, severity, status, dates, category).
  - Logs to `/var/ossec/logs/integrations.log`.
- `sanernow_rules.xml`: rules `311000`-`311003` (base, missing patch, high/critical missing patch, remediation). Uses the built-in JSON decoder, so no custom decoder is needed.
- `sample_logs/sanernow_sample_events.json`: mock events in the script's output format for testing with `wazuh-logtest`.
- `README.md`: setup and testing guide that follows the integration README template in `CONTRIBUTING.md`, including the `command` wodle configuration and notes on storage and correlation with Vulnerability Detection.

## Testing

- [ ] Rules tested with `wazuh-logtest` using `sample_logs/sanernow_sample_events.json`.
- [ ] Script not tested against a SanerNow tenant (no access to one; the customer did not share API samples).

## Checklist

- [x] Directory name is lowercase and underscore separated.
- [x] Includes a `README.md` that follows the template in `CONTRIBUTING.md`.
- [x] Includes the rules file (no custom decoders needed: JSON events).
- [x] No credentials or customer data in the files.
