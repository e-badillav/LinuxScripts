# WS-41354 - Reglas Cloudflare WAF (Toks / Cyberpeace)

Reglas de correlacion pedidas por el SOC del cliente en los comentarios del
ticket [WS-41354](https://wazuh-support.atlassian.net/browse/WS-41354),
complementarias al set ya consolidado en
`toks_custom_rules_consolidated.xml` (adjunto al ticket, SIDs 100190-100196,
199500-199543, 199600-199665).

## Archivos

- `toks_cloudflare_waf_soc_scenarios.xml` - las 10 reglas nuevas (199700-199722).
- `toks_own_infra_ips` - CDB list placeholder para la regla 199705 (IPs de
  infraestructura propia). **Hay que poblarla con datos reales del cliente
  antes de activar 199705.**

## Mapeo escenario -> reglas

| Escenario del ticket | Reglas | Nivel |
|---|---|---|
| 1. Enumeracion API / IDOR (`taco-line/contacts/phone/{numero}`) - patron de volumen | 199700 (base), 199701 | 3 / 12 (alta) |
| 1. Mismo endpoint, 200 fuera de horario o desde IP externa | 199702 (base 200), 199703 (fuera de horario), 199704 (fin de semana), 199705 (IP fuera de infra propia) | 7 / 14 / 14 / 14 (critica) |
| 2. Abuso de token portal cautivo `/new-password?kds=` - referer externo | 199710 (hija de la base 92511 ya existente) | 10 |
| 2. Mismo abuso, 5+ veces en 5 min desde la misma IP | 199711 (hija de 92511) | 13 (critica) |
| 3. Acceso a rutas SQL/backup/config | 199720 (visibilidad) | 5 |
| 3. Archivo SQL/backup servido con 200 (brecha confirmada) | 199721 | 15 (critica, notificacion inmediata) |
| 3. 5+ rutas SQL/backup distintas en 10 min desde la misma IP | 199722 | 12 |

## Decisiones tomadas y por que

- **No se filtra por user-agent en 199700**: el ticket describe curl/axios
  como comportamiento *tipico* del abuso, no como condicion. Filtrar por UA
  dejaria pasar la misma enumeracion hecha con otro cliente HTTP.
- **"Mas de 10 peticiones en 2 minutos" -> `frequency="11" timeframe="120"`**:
  en Wazuh, `frequency=N` dispara al alcanzar N coincidencias, asi que "mas
  de 10" requiere 11.
- **"Fuera de horario de negocio"** se implemento con dos reglas hijas
  independientes (199703 por rango horario diario, 199704 por fin de
  semana) porque Wazuh no permite combinar `<time>` y `<weekday>` en OR
  dentro de una sola regla; el rango 08:00-20:00 Mexico/CST es un
  placeholder a confirmar con el cliente.
- **"IP que no sea parte de la infraestructura propia"** se implemento con
  una CDB list (`toks_own_infra_ips`) y `lookup="not_address_match_key"`,
  que es el metodo correcto de Wazuh para negar sobre campos de IP (no
  `not_match_key`, que es para campos no-IP).
- **Escenario 2 - dominio "propio" vs "externo"**: se armo la lista de
  dominios propios con los que aparecen en las muestras de log adjuntas
  (toks.com.mx, shakeshack.com.mx, acomerclub.com.mx, elfarolito.com.mx).
  El SOC menciona `kloudspot.com` (proveedor de portal cautivo) como
  ejemplo de dominio a vigilar, pero en los logs reales aparece como
  referer legitimo del mismo flujo de `/new-password` - **confirmar con el
  cliente si Kloudspot debe tratarse como dominio propio/autorizado antes
  de usar esta regla para bloqueo activo**, para evitar falsos positivos
  sobre su propio proveedor.
- **Regla base 92511 no se reescribe**: el ticket indica que ya existe
  (nivel 7, en `cloudflare_waf_overwrite.xml`, fuera de este archivo). Las
  reglas 199710/199711 solo la referencian via `if_sid`/`if_matched_sid`.

## Evidencia real ya encontrada en las muestras adjuntas al ticket

- **Brecha confirmada (escenario 3b)**: `136.67.185.85` obtuvo HTTP 200 en
  `/sql/backup.sql`, `/sql/dump.sql` y `/sql/db.sql` sobre `www.toks.com.mx`
  el 2026-09-04 11:34:40Z (`Logs-SQL.xlsx`). Esto dispara la regla 199721
  y deberia revisarse/confirmarse con el cliente si aun no se hizo.
- Los ejemplos de `/admin/sql%2econf`, `/1.sql`, `/sql/dump.sql`, etc. de
  `Logs-SQL.xlsx` se probaron manualmente contra el patron de 199720 y
  todos coinciden.
- La muestra de `taco-line.xlsx` no tiene un burst real que supere el
  umbral de 199701 (>10 en 2 min) desde una sola IP, pero si un caso
  cercano (una IPv6 con 41 peticiones en ~42 minutos vía curl); la regla
  se dejo con el umbral pedido por el SOC en vez de ajustarla a esta
  muestra puntual.
- `SQLi.xlsx` contiene un ataque real de SQL injection contra
  `/Form/FormRegistrarUsuario.aspx?lang=` (payloads UNION SELECT), ya
  cubierto por las reglas 199610/199618/199660/199663 del consolidado
  existente del cliente - no requirio reglas nuevas.

## Pendiente / a validar con el cliente antes de pasar a produccion

1. Confirmar mapeo `data.ClientIP` -> `srcip` con `wazuh-logtest` (mismo
   prerequisito que ya documenta el cliente en su consolidado). Si no se
   mapea, cambiar `<same_srcip/>` por `<same_field>data.ClientIP</same_field>`
   en 199701, 199711 y 199722.
2. Poblar `toks_own_infra_ips` con IPs/rangos reales antes de activar 199705.
3. Confirmar horario de negocio real (199703) y si Kloudspot cuenta como
   dominio propio (199710).
4. Confirmar que el nivel 15 de 199721 efectivamente dispara notificacion
   inmediata en la configuracion de alertas del cliente (email_alert_level
   / integracion usada).
