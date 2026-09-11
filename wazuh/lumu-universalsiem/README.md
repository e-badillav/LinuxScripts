# Lumu UniversalSIEM — Decoders y Reglas (WS-41500)

Decoders y reglas personalizados para los logs de **UniversalSIEM**, el
conector/forwarder que Lumu utiliza para enviar sus incidentes al SIEM del
cliente (ticket [WS-41500](https://wazuh-support.atlassian.net/browse/WS-41500)).

## Formato del log

```
<timestamp> | <LEVEL> | <módulo> <función> <línea> | <mensaje>
```

Ejemplo:

```
Sep 10 19:35:30 | INFO | event_dispatcher dispatch 13 | UniversalSIEM - Sending [Event: NewIncidentCreated + IncidentId: c7cc5ef0-ad4e-11f1-85aa-13eca15c3bb0 + Adversaries type: Malware]
```

El `wazuh-logtest` compartido por el cliente muestra `No decoder matched`
porque ningún decoder por defecto reconoce este formato (el pre-decoding
estándar de syslog incluso interpreta mal el primer `|` como si fuera el
hostname). Los decoders de este directorio resuelven eso.

## Archivos

- `decoders.xml` — decoder padre `lumu-universalsiem` (extrae `log_level`,
  `module`, `function`, `line`) más 7 decoders hijo para los distintos
  tipos de mensaje observados en los logs compartidos:
  - `lumu-universalsiem-startup` — arranque del programa.
  - `lumu-universalsiem-thread` — hilos de trabajo iniciados.
  - `lumu-universalsiem-websocket` — apertura del WebSocket.
  - `lumu-universalsiem-labels` — carga de `LabelsCache`.
  - `lumu-universalsiem-queue-add` — mensaje encolado (`event_type`, `queue`, `queue_size`).
  - `lumu-universalsiem-queue-status` — consumo de la cola (`queue`, `queue_pending`).
  - `lumu-universalsiem-processing` — evento individual en procesamiento (`event_type`, `incident_id`, `processed_index`, `processed_total`).
  - `lumu-universalsiem-dispatch` — envío del evento (`event_type`, `incident_id`, `adversary_type`).
- `rules.xml` — 12 reglas (`100700`-`100711`) agrupadas en `lumu,universalsiem,`:
  - `100700` (nivel 0): regla base de agrupación, sin alerta.
  - `100701`-`100707` (nivel 3): eventos operativos/informativos del propio
    conector (arranque, hilos, WebSocket, labels, actividad de colas).
  - `100708` `NewIncidentCreated` (nivel 5), `100709` `IncidentUpdated`
    (nivel 5) y `100710` `IncidentBuiltInResponseUpdated` (nivel 7): se
    disparan cuando UniversalSIEM despacha (`Sending [...]`) un incidente,
    incluyendo `incident_id` y `adversary_type` en la descripción.
  - `100711` (nivel 10): escala cualquiera de las tres reglas anteriores
    cuando `adversary_type` es `Malware`.

  Los IDs `100700`-`100711` están dentro del rango reservado para reglas
  locales/personalizadas (100000-120000); ajústalos si ya usas ese rango.

## Instalación

En el manager (On-Premise; en Wazuh Cloud se gestiona vía API/consola):

```bash
cp decoders.xml /var/ossec/etc/decoders/local_decoder_lumu.xml
cp rules.xml    /var/ossec/etc/rules/local_rules_lumu.xml
chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder_lumu.xml /var/ossec/etc/rules/local_rules_lumu.xml
/var/ossec/bin/wazuh-control restart
```

Los directorios `etc/decoders` y `etc/rules` ya están incluidos por defecto
en `ossec.conf` (`<ruleset><decoder_dir>` / `<rule_dir>`), no hace falta
editar la config para que se carguen.

### Recepción de los logs

Si UniversalSIEM escribe a un archivo local en el host donde corre el
agente, se necesita un bloque `<localfile>` en el `ossec.conf` del agente
(ajustar la ruta real):

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/ruta/al/log/de/universalsiem.log</location>
</localfile>
```

Si en cambio llega por syslog remoto al manager, confirmar con el cliente
el puerto/formato configurado en la recepción de syslog del manager.

## Validación con wazuh-logtest

```bash
/var/ossec/bin/wazuh-logtest
```

Pegar, por ejemplo:

```
Sep 10 19:35:30 | INFO | event_dispatcher dispatch 13 | UniversalSIEM - Sending [Event: NewIncidentCreated + IncidentId: c7cc5ef0-ad4e-11f1-85aa-13eca15c3bb0 + Adversaries type: Malware]
```

Resultado esperado: decoder `lumu-universalsiem-dispatch` con
`incident_id`, `event_type` y `adversary_type` extraídos, y disparo de la
regla `100708` (nivel 5) más la `100711` (nivel 10, por `Malware`).

Todas las líneas del log compartido por el cliente (arranque, hilos,
WebSocket, colas, incidentes) fueron probadas contra estos decoders/reglas
antes de entregarlos.

## Pendiente con el cliente

- Confirmar la ruta real del archivo de log (o el mecanismo de envío) para
  configurar el `<localfile>`/recepción de syslog correspondiente.
- Confirmar si existen otros niveles de log (`WARN`, `ERROR`) o tipos de
  evento (`Adversaries type` distintos a `Malware`) que quieran alertas
  específicas — los decoders ya capturan `log_level` y `adversary_type`
  como campos genéricos por si se necesitan reglas adicionales.
