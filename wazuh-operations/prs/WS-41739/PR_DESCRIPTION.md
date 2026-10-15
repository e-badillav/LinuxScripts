## Description

Adds decoders and rules for Kaspersky Security Center Cloud Console events received through syslog: Kaspersky Endpoint Security events (in Spanish) and Administration Server audit events.

Related ticket: WS-41739

## Changes

New directory `content/ruleset/kaspersky_cloud/`:

- `kaspersky_decoders.xml`: parent decoder `kaspersky-cloud` and sibling decoders that extract:
  - KES fields (event type, process, result, threat type and name, user, object, hashes, component), separated by the literal `\r\n` characters in the message.
  - Administration Server audit fields (user and source IP of console connections).
  - Fields from the structured `[event@23668 ...]` block (event code and description, server name and IP, group, KSC FQDN).
- `kaspersky_rules.xml`: rules `100200`-`100210` for malware detections (split by whether the threat was remediated), protection components stopped or disabled, outdated databases, group policy, KSN status and console connections.
- `sample_logs/kaspersky_cloud_events.log`: 30 sample events (hostnames, tenant IDs and IPs anonymized).
- `README.md`: setup and testing guide that follows the integration README template in `CONTRIBUTING.md`.

## Testing

- [x] Decoders and rules tested by the customer in their environment with the same events.
- [ ] Tested with `wazuh-logtest` using `sample_logs/kaspersky_cloud_events.log`.

## Checklist

- [x] Directory name is lowercase and underscore separated.
- [x] Includes a `README.md` that follows the template in `CONTRIBUTING.md`.
- [x] Includes the rules and decoders files.
- [x] No credentials or customer data in the files.
