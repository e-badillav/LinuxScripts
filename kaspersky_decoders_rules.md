# Kaspersky decoders and rules (WS-41739)

Custom Wazuh decoders and rules for the Kaspersky Endpoint Security (KES) /
Kaspersky Security Center (KSC) events attached to
[WS-41739](https://wazuh-support.atlassian.net/browse/WS-41739).

Files:

- `kaspersky_decoders.xml` - three decoders: `kaspersky-kes`,
  `kaspersky-ksc-audit`, `kaspersky-ksc-detailed`.
- `kaspersky_rules.xml` - rules `100200`-`100216`, built on those decoders.

Both files were validated against all 30 sample events in the ticket's
attachment (byte-for-byte, simulating PCRE2 in non-UTF8/byte mode) before
being written here; see "Testing" below to reproduce that with
`wazuh-logtest` on a real manager.

## The three log shapes in the sample

Kaspersky sends events over syslog as `<program>|<version> <message>`
(no colon after the program name, so Wazuh's automatic `program_name`
extraction does not kick in - the decoders below match the full log
instead). Three shapes were present in the sample:

1. **`kaspersky-kes`** - the raw KES endpoint agent log. Fields are
   separated by a *literal* two-character `\r\n` (backslash-r-backslash-n,
   not an actual line break) and the block starts with a UTF-8 BOM:

   ```
   KES|11.0.0.0 <BOM>Tipo de evento: No se puede desinfectar\r\nNombre: SearchProtocolHost.exe\r\n...
   ```

2. **`kaspersky-ksc-audit`** - a plain KSC Administration Server audit
   sentence:

   ```
   1093|1.0.0.0 User "alice" has connected to the Administration Server from "10.0.0.5".
   ```

3. **`kaspersky-ksc-detailed`** - the same kind of KSC event, but wrapped
   in an RFC5424-style structured-data block tagged with Kaspersky's IANA
   PEN (23668). This shape is generic - it pulls out whatever
   `et`/`etdn`/`tdn`/`hdn`/`hip`/`gn`/`kscfqdn`/`p2`/`p3`/`p5`/`p9`
   attributes are present, so it also covers KSC event codes that were not
   in the sample:

   ```
   1093|1.0.0.0 - KLAUD_EV_SERVERCONNECT [event@23668 p2="10.0.0.5" p3="alice" et="KLAUD_EV_SERVERCONNECT" etdn="Audit (connection to the Administration Server)" hdn="<Administration Server>" hip="127.0.0.1" gn="Managed devices" kscfqdn="ksc.example.local"] User "alice" has connected...
   ```

**Known quirk:** for the numeric `et` codes (e.g. `000007e6`), the KSC
server re-emits the endpoint's own message inside this shape, but with
accented characters (á,é,í,ó,ú,ñ) each replaced by two literal dots -
`"aplicación"` becomes `"aplicaci..n"`. The generic decoder still captures
`et`/`etdn`/`hdn`/etc. correctly; only the free-text `kaspersky.message`
field is affected, and rule `100216` deliberately matches on the numeric
`et` code rather than the (possibly mangled) `etdn` text for this reason.

## Assumption about log collection

The decoders assume Wazuh's syslog collection has already stripped the
leading `<timestamp> <hostname> ` from the line (standard behaviour for
syslog received via the agent's `syslog` localfile type, or via a Wazuh
agent acting as a syslog relay per the workaround discussed on the
ticket). Each decoder's `prematch` also tolerates that prefix still being
present, so nothing breaks if the events instead reach the manager through
a script/API integration that keeps the full raw line - see the ticket
comment for the suggested "relay agent" and "pull via API" integration
options.

## Installation

1. Copy `kaspersky_decoders.xml` to `/var/ossec/etc/decoders/` on the
   manager (or into the agent's `ossec.conf` decoder path if decoding
   locally).
2. Copy `kaspersky_rules.xml` to `/var/ossec/etc/rules/`.
3. Rule IDs `100200`-`100216` are in the local custom range; check they
   don't collide with rules you already have in that range and renumber
   if needed.
4. Restart the manager: `systemctl restart wazuh-manager`.

## Testing with wazuh-logtest

Use the raw lines from the ticket's sample file directly (including the
literal `\r\n` sequences and the leading timestamp/hostname, since
`wazuh-logtest` runs the full decoding pipeline):

```
/var/ossec/bin/wazuh-logtest
```

then paste, e.g.:

```
2026-09-18T18:37:52.000Z minint-hogfup9 KES|11.0.0.0 ﻿Tipo de evento: No se puede desinfectar\r\nNombre: SearchProtocolHost.exe\r\nRuta de la aplicación: C:\Windows\System32\r\nID del proceso: 840\r\nDescripción del resultado: No procesado\r\nTipo: Virus\r\nNombre: EICAR-Test-File\r\nUsuario: WORKGROUP\MININT-HOGFUP9$ (Iniciador)\r\nObjeto: C:\Users\Administrator\Desktop\eicar.txt\r\nRazón: No se puede desinfectar\r\nSHA256: 8B3F191819931D1F2CEF7289239B5F77C00B079847B9C2636E56854D1E5EFF71\r\nMD5: E7E5FA40569514EC442BBDF755D89C2F
```

Expected: `decoder: 'kaspersky-kes'`, rule `100203` at level 12, with
`kaspersky.threat_name = EICAR-Test-File` and `kaspersky.object =
C:\Users\Administrator\Desktop\eicar.txt`.

## Decoded fields

`kaspersky-kes` -> `data.kaspersky.*`: `event_type`, `process_name`,
`application_path`, `process_id`, `user`, `component`, `result`,
`threat_type`, `threat_name`, `threat_level`, `precision`, `object_type`,
`object`, `object_path`, `object_name`, `reason`, `sha256`, `md5`. Not
every field is present on every event type - each is optional and only
extracted when the corresponding "Label: value" line exists in the log.

`kaspersky-ksc-audit` -> `srcuser`, `srcip` (Wazuh reserved fields).

`kaspersky-ksc-detailed` -> `data.kaspersky.*`: `event_id`, `et`, `etdn`,
`tdn`, `hdn`, `hip`, `gn`, `kscfqdn`, `p2`, `p3`, `p5`, `p9`, `message`.

## Rules

| ID     | Level | Fires on                                                   |
|--------|-------|--------------------------------------------------------------|
| 100200 | 3     | Base: any `kaspersky-kes` event                              |
| 100201 | 3     | Base: any `kaspersky-ksc-audit` event                         |
| 100202 | 3     | Base: any `kaspersky-ksc-detailed` event                      |
| 100203 | 12    | KES: "No se puede desinfectar" (malware not disinfected)     |
| 100204 | 10    | KES: "Objeto eliminado" (malicious object deleted)            |
| 100205 | 7     | KES: "Se ha creado una copia de seguridad del objeto"         |
| 100206 | 6     | KES: signature databases severely outdated                   |
| 100207 | 5     | KES: a protection task/component was stopped                 |
| 100208 | 12    | 100207 narrowed to a security-critical component (Firewall,  |
|        |       | file/web/network threat protection, HIPS, Anti-Cryptor,      |
|        |       | exploit prevention) - possible tampering                     |
| 100209 | 12    | KES: all protection components disabled - possible tampering |
| 100210 | 3     | KES: group policy applied                                    |
| 100211 | 3     | KES: KSN servers available                                    |
| 100212 | 3     | KES: KSN participation enabled                                |
| 100213 | 3     | KSC audit: OpenAPI service-account connection                |
| 100214 | 5     | KSC audit: admin connected from a non-local address           |
| 100215 | 3     | KSC detailed: `KLAUD_EV_SERVERCONNECT` (admin console login)  |
| 100216 | 3     | KSC detailed: numeric KSN-status codes `000007e6`/`000007e4`  |

## Extending

The sample only shows a handful of the many "Tipo de evento" / `et` values
KES and KSC can emit. To add another:

- For a plain KES agent event: add a rule under `if_sid 100200` matching
  `kaspersky.event_type` with the new Spanish string, same as `100206`-
  `100212`.
- For a KSC structured-data event with a new `et`/`etdn`: add a rule under
  `if_sid 100202` matching `kaspersky.et` or `kaspersky.etdn` - the decoder
  already extracts them generically, no decoder change needed.
