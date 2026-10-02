# Lumu UniversalSIEM: decoders y reglas para Wazuh (WS-41500)

## Archivos

| Archivo | Destino en el manager |
| --- | --- |
| `lumu_decoders.xml` | `/var/ossec/etc/decoders/lumu_decoders.xml` |
| `lumu_rules.xml` | `/var/ossec/etc/rules/lumu_rules.xml` |

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/lumu_decoders.xml /var/ossec/etc/rules/lumu_rules.xml
chmod 660 /var/ossec/etc/decoders/lumu_decoders.xml /var/ossec/etc/rules/lumu_rules.xml
systemctl restart wazuh-manager
```

En un clúster se copian solo en el nodo master, que los sincroniza con los workers.

## Campos que se extraen

`lumu.log_level`, `lumu.module`, `lumu.function`, `lumu.line`, `lumu.queue`,
`lumu.queue_size`, `lumu.event_type`, `lumu.incident_id`, `lumu.adversary_type`.

## Reglas (IDs 111000-111099)

Solo las líneas `Sending [Event: ...]` (el evento que el conector envía de verdad)
generan alertas de incidente. Las líneas de cola (`added to ... queue`, `being
processed`) solo se decodifican (nivel 0) para no duplicar alertas.

| Tipo de adversario (`lumu.adversary_type`) | NewIncidentCreated | IncidentUpdated |
| --- | --- | --- |
| C2C | 111011 (15) | 111021 (14) |
| Malware | 111012 (15) | 111022 (14) |
| DGA | 111013 (14) | 111023 (12) |
| Mining | 111014 (14) | 111024 (12) |
| Phishing | 111015 (14) | 111025 (12) |
| Anonymizer | 111016 (12) | 111026 (10) |
| Spam | 111017 (10) | 111027 (8) |
| Cualquier otro tipo | 111010 (3) | 111020 (3) |

Otras reglas: 111001 (la integración se inició, 3), 111002 (WebSocket abierto, 3),
111003 (log ERROR/CRITICAL del conector, 5) y 111030 (IncidentBuiltInResponseUpdated, 3).

## Prueba con wazuh-logtest

```
/var/ossec/bin/wazuh-logtest
Sep 10 19:35:30 | INFO | event_dispatcher dispatch 13 | UniversalSIEM - Sending [Event: NewIncidentCreated + IncidentId: c7cc5ef0-ad4e-11f1-85aa-13eca15c3bb0 + Adversaries type: Malware]
```

Resultado esperado: decoder `lumu-universalsiem`, regla `111012`, nivel 15.
