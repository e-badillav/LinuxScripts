## Description

Adds an Okta integration that collects Okta System Log events and ingests them into Wazuh.

Related ticket: WS-39601

## Changes

New directory `integrations/okta/`:

- `scripts/okta_api.py`: Python script that polls the Okta System Log API (`/api/v1/logs`) and sends each event to the Wazuh `analysisd` socket as `{"okta": <event>}`.
  - State file (`/var/ossec/integrations/.okta_state`) so events are not fetched twice.
  - Pagination through the `Link: rel="next"` header.
  - Handles HTTP 429 using `X-Rate-Limit-Reset` with exponential backoff.
- `ruleset/okta_decoders.xml`: decoders for the Okta event fields (actor, client, authentication context, outcome, security context, debug data, request IP chain and targets).
- `ruleset/okta_rules.xml`: rules `310001`-`310009` for OIDC token grants, LDAP reads by the AD agent, MFA authentication, sign-on policy evaluation, email delivery, user creation/activation/deactivation and password resets.
- `sample_logs/okta_sample_event.json`: sample event for testing with `wazuh-logtest`.
- `README.md`: setup and testing guide that follows the integration README template in `CONTRIBUTING.md`. Covers scheduling with either the `command` wodle or cron.

## Testing

- [ ] Decoders and rules tested with `wazuh-logtest` using `sample_logs/okta_sample_event.json`.
- [ ] Script tested against an Okta tenant, with events showing in `archives.json` and alerts in the dashboard.

## Checklist

- [x] Directory name is lowercase and underscore separated.
- [x] Includes a `README.md` that follows the template in `CONTRIBUTING.md`.
- [x] Includes the rules and decoders files.
- [x] No credentials or customer data in the files.
