# Contrato de API

## `GET /health`

Devuelve `200`:

```json
{"status":"ok","module":"06-soar"}
```

## Autenticación (HU20)

Salvo `GET /health`, todos los endpoints exigen `Authorization: Bearer <token>`. El SOAR no valida
el JWT localmente: valida cada petición, sin caché, mediante `GET {AUTH_URL}/auth/validate` del
Módulo 1 (grupo 1). Identidad devuelve `200` con `{valid, user_id, username, role}` si el token es
válido, o `401` si no lo es.

### Permisos por endpoint

| Endpoint | Roles permitidos |
|---|---|
| `GET /incidents` | `analista`, `admin`, `servicio` |
| `GET /incidents/{id}/responses` | `analista`, `admin`, `servicio` |
| `GET /incidents/{id}/history` | `analista`, `admin`, `servicio` |
| `GET /metrics` | `analista`, `admin`, `servicio` |
| `GET /blacklist` | `analista`, `admin`, `servicio` |
| `POST /incidents/{id}/status` | `analista`, `admin` |
| `POST /poll` | `analista`, `admin` |
| `GET /health` | Público (lo usan el healthcheck de `docker-compose` y el CI) |

### Errores de autenticación

- `401` `{"error": "unauthorized"}`: falta el token, no usa esquema Bearer o Identidad indica que no es válido.
- `403` `{"error": "forbidden"}`: el token es válido, pero su rol no tiene permiso para el endpoint.
- `503` `{"error": "identity_unavailable"}`: Identidad no responde, tarda más de 5 segundos o devuelve un error.

La autenticación se comprueba antes de procesar la ruta: una petición a un incidente inexistente sin token
devuelve `401`, no `404`.

> **IMPORTANTE para el Dashboard:** el SOAR NUNCA devuelve `401` cuando Identidad está caído; devuelve
> `503`. Así, `api-estado.js` del grupo 7, que borra la sesión al recibir un `401`, no expulsa a los
> usuarios si Identidad se cae durante la demo. Tratad `503` como «servicio no disponible, reintentar».

### Identidad de quien cambia un estado

Si la petición trae un token válido, `changed_by` se toma del `username` del token. El valor
`changed_by` enviado en el cuerpo se ignora sin error. Los cambios automáticos siguen usando
`soar-automation`. El Dashboard debe reenviar el token del usuario que ha iniciado sesión (no un
token de servicio), para que `changed_by` sea el analista real.

### Configuración

La URL de Identidad se lee de `AUTH_URL` o, si no está definida, de `IDENTITY_URL`. Es la misma
configuración que usa HU21 para el login de `svc-soar`. Si ninguna está configurada, el SOAR deja los
endpoints abiertos y escribe un `WARNING` en el log (modo de desarrollo y tests); en el `docker-compose`
global debe configurarse.

### Ejemplos con `curl`

`<SOAR_URL>` es la URL del SOAR; dentro de la red del docker-compose, `http://soar` (puerto 80).

Petición autenticada:

```sh
curl -i -H "Authorization: Bearer <token>" '<SOAR_URL>/metrics'
```

Respuestas de error:

```sh
# Token ausente, no Bearer o inválido:
curl -i '<SOAR_URL>/incidents/INC-INEXISTENTE/history'
```

```json
{"error": "unauthorized"}
```

```sh
# Token válido con rol servicio (sin permiso para POST):
curl -i -H "Authorization: Bearer <token>" -X POST '<SOAR_URL>/poll'
```

```json
{"error": "forbidden"}
```

```sh
# Identidad no disponible:
curl -i -H "Authorization: Bearer <token>" '<SOAR_URL>/metrics'
```

```json
{"error": "identity_unavailable"}
```

Fecha efectiva: pendiente de anunciar en el SoS.

## `GET /incidents`

Devuelve `200` con una lista directa de incidentes (`[]` si no hay ninguno). Es el **formato único
publicado** para el grupo 7: los campos nunca se renombran ni se eliminan; como mucho se añaden.

### Campos

| Campo | Tipo | Admite `null` | Significado |
|---|---|---|---|
| `id` | entero | No | Identificador interno de la fila en la tabla `incidents` |
| `alert_key` | string | No | Clave de idempotencia de la alerta (`alert_id`, `id` o SHA-256) |
| `alert` | objeto | No | Alerta cruda tal como la envió el SIEM |
| `first_seen` | string ISO 8601 con zona | No | Primera vez que el SOAR recibió la alerta |
| `incident_id` | string | Sí | Identificador del incidente normalizado (`INC-XXXXXX`) |
| `alert_id` | string | Sí | Identificador de la alerta del SIEM |
| `event_type` | string | Sí | Tipo de evento, por ejemplo `fuerza_bruta` o `port_scan` |
| `severity` | string | Sí | Severidad: `low`, `medium`, `high` o `critical` |
| `priority` | string | Sí | Prioridad calculada por HU5: `low`, `medium`, `high` o `critical` (ver `priority.md`) |
| `source_ip` | string | Sí | IP de origen |
| `status` | string | Sí | Estado del incidente (HU6): `open`, `in_progress`, `contained` o `closed` |
| `created_at` | string ISO 8601 con zona | Sí | Creación del incidente normalizado |
| `resolved_at` | string ISO 8601 con zona | Sí | Cierre del incidente; `null` mientras no esté `closed` |
| `applied_playbook` | string | Sí | Playbook ejecutado sobre el incidente (ver la regla más abajo) |
| `automation` | objeto | Sí | Decisión de HU13: `{"automatable": bool, "playbook": string o null, "reason": string}` |
| `responses` | lista de objetos | No (lista vacía) | Respuestas ejecutadas (HU15), con el formato de `executed_response.md` |

Las filas guardadas antes del Sprint 2 no tienen incidente normalizado: devuelven todos los campos
que admiten `null` a `null` y `responses` como `[]`.

**Datos sensibles (HU12.1).** `credential` y `username` se sustituyen por `"***"` en cualquier nivel de
`alert` (también dentro de `details`); en la base de datos la alerta se guarda entera.

Hay ejemplos generados con la API real en [`api-examples/`](api-examples/README.md).

### Regla de `applied_playbook`

- Vale el nombre del playbook (campo `playbook` de sus respuestas ejecutadas, hoy `"brute_force"`)
  si el incidente tiene **al menos una** respuesta registrada, **sea cual sea su `status`**
  (`success`, `failed` o `skipped`).
- Vale `null` si el incidente no tiene ninguna respuesta.
- `applied_playbook` **no** indica si la respuesta tuvo éxito: el resultado de cada acción está en
  `responses[].status`, y el motivo en `responses[].message` (éxito) o `responses[].error` (fallo u omisión).

### Ejemplo: incidente automatizado y contenido (`block_ip` en `success`, `notify` en `skipped`)

Respuesta con `GROUP7_NOTIFY_URL` sin configurar, como en la demo. `block_ip` mete la IP en la lista
negra simulada (HU19), así que el incidente pasa a `in_progress` y después a `contained`
(ver `playbook.md` y `status.md`). Si ninguna acción tuviera éxito, seguiría en `open`.

```json
{
  "id": 2,
  "alert_key": "SIEM-ALERT-EJEMPLO-002",
  "alert": {
    "alert_id": "SIEM-ALERT-EJEMPLO-002",
    "description": "El honeypot ha registrado un evento clasificado como fuerza bruta sobre SSH.",
    "details": {
      "command": null,
      "credential": "***",
      "service": "ssh",
      "source_ip": "192.168.1.50",
      "username": "***"
    },
    "event_id": "HP-981839239323",
    "event_type": "fuerza_bruta",
    "severity": "medium",
    "source": "honeypot",
    "source_ip": "192.168.1.50",
    "target_ip": null,
    "timestamp": "2026-09-22T18:30:15Z",
    "title": "Intento de fuerza bruta en el honeypot"
  },
  "first_seen": "2026-11-04T19:44:51.322604+00:00",
  "incident_id": "INC-F98CDC",
  "alert_id": "SIEM-ALERT-EJEMPLO-002",
  "event_type": "fuerza_bruta",
  "severity": "medium",
  "priority": "medium",
  "source_ip": "192.168.1.50",
  "status": "contained",
  "created_at": "2026-11-04T19:44:51.322604+00:00",
  "resolved_at": null,
  "applied_playbook": "brute_force",
  "automation": {
    "automatable": true,
    "playbook": "brute_force",
    "reason": "Incidente compatible con automatizacion"
  },
  "responses": [
    {
      "response_id": "RES-1B07E4",
      "incident_id": "INC-F98CDC",
      "playbook": "brute_force",
      "action": "block_ip",
      "status": "success",
      "triggered_by": "automatic",
      "executed_at": "2026-11-04T19:44:51.330219Z",
      "finished_at": null,
      "message": "IP 192.168.1.50 bloqueada",
      "error": null,
      "details": {
        "target": "192.168.1.50",
        "execution_id": "4f31ca91-ab2b-416f-b420-1711ad4b6a11",
        "playbook_status": "PARTIAL"
      }
    },
    {
      "response_id": "RES-20A761",
      "incident_id": "INC-F98CDC",
      "playbook": "brute_force",
      "action": "notify",
      "status": "skipped",
      "triggered_by": "automatic",
      "executed_at": "2026-11-04T19:44:51.330219Z",
      "finished_at": null,
      "message": null,
      "error": "GROUP7_NOTIFY_URL no está configurada",
      "details": {
        "target": "group7",
        "execution_id": "4f31ca91-ab2b-416f-b420-1711ad4b6a11",
        "playbook_status": "PARTIAL"
      }
    }
  ]
}
```

### Ejemplo: incidente no automatizable

```json
{
  "id": 1,
  "alert_key": "SIEM-ALERT-EJEMPLO-001",
  "alert": {
    "alert_id": "SIEM-ALERT-EJEMPLO-001",
    "description": "Una IP ha contactado con 20 puertos del mismo destino en 60 segundos.",
    "details": {
      "distinct_ports_count": 20,
      "protocol": "tcp",
      "rule_id": "IDS-001",
      "source_ip": "192.168.1.50",
      "target_ip": "192.168.1.10",
      "window_seconds": 60
    },
    "event_id": "IDS-EJEMPLO-001",
    "event_type": "port_scan",
    "severity": "medium",
    "source": "ids",
    "source_ip": "192.168.1.50",
    "target_ip": "192.168.1.10",
    "timestamp": "2026-09-22T18:30:15Z",
    "title": "Posible escaneo de puertos"
  },
  "first_seen": "2026-11-04T19:44:51.315637+00:00",
  "incident_id": "INC-218F88",
  "alert_id": "SIEM-ALERT-EJEMPLO-001",
  "event_type": "port_scan",
  "severity": "medium",
  "priority": "medium",
  "source_ip": "192.168.1.50",
  "status": "open",
  "created_at": "2026-11-04T19:44:51.314202+00:00",
  "resolved_at": null,
  "applied_playbook": null,
  "automation": {
    "automatable": false,
    "playbook": null,
    "reason": "No existe un playbook para el tipo de evento 'port_scan'"
  },
  "responses": []
}
```

## `GET /incidents/{incident_id}/responses`

Devuelve `200` con la lista de respuestas ejecutadas del incidente (ver `executed_response.md`).
Si el incidente no existe devuelve `404` `{"error":"incident_not_found"}`.

## `GET /incidents/{incident_id}/history`

Devuelve `200` con los cambios de estado del incidente (HU7), del más antiguo al más reciente.
Cada elemento tiene `from_status`, `to_status`, `justification`, `resolution_reason`, `changed_by`
y `changed_at` (UTC, terminado en `Z`). Detalle de los campos en `status.md`.

- Sin cambios de estado: `200` con `[]`.
- Si el incidente no existe devuelve `404` `{"error":"incident_not_found"}`.

Ejemplo de un incidente de fuerza bruta contenido automáticamente (es `api-examples/history.json`):

```json
[
  {
    "from_status": "open",
    "to_status": "in_progress",
    "justification": "Respuesta automática ejecutada: block_ip",
    "changed_at": "2026-11-26T10:00:00.018000Z",
    "resolution_reason": null,
    "changed_by": "soar-automation"
  },
  {
    "from_status": "in_progress",
    "to_status": "contained",
    "justification": "IP 192.168.1.50 bloqueada en la lista negra",
    "changed_at": "2026-11-26T10:00:00.025000Z",
    "resolution_reason": null,
    "changed_by": "soar-automation"
  }
]
```

## `POST /incidents/{incident_id}/status`

Cambia el estado del incidente según HU6 (ver `status.md`). Cuerpo:

```json
{"status":"closed","justification":"Revisado por el analista","resolution_reason":"IP bloqueada","changed_by":"analista.fer"}
```

- Con un token válido, `changed_by` sale del `username` del token y es opcional en el cuerpo. Sin
  autenticación (`AUTH_URL` no configurada), el cuerpo debe incluirlo al cerrar y es opcional en
  el resto de cambios. Máximo 100 caracteres.
- `200` con el incidente actualizado y `changed_by`. Al cerrar, `resolved_at` se rellena.
- `400` `{"error":"..."}` si el cuerpo no es válido o HU6 rechaza el cambio. Sin autenticación,
  también si `changed_by` del cuerpo no es texto o falta al cerrar. Si el `changed_by` efectivo
  (del token o del cuerpo) supera 100 caracteres, también se devuelve `400`.
- `404` `{"error":"incident_not_found"}` si el incidente no existe.
- `401`, `403` o `503` por errores de autenticación; ver [Autenticación (HU20)](README.md#autenticación-hu20).

## `POST /poll`

Consulta `GET /alerts` en `SIEM_URL`. Acepta tanto una lista de alertas como
`{"alerts":[...]}`. Devuelve `200`:

```json
{"received":3,"created":1,"ignored":1,"rejected":1,"automated":1}
```

| Contador | Significado |
|---|---|
| `received` | Alertas recibidas del SIEM |
| `created` | Incidentes nuevos |
| `ignored` | Alertas repetidas (se registran en los logs) |
| `rejected` | Alertas que no cumplen el contrato del SIEM (log `WARNING`) |
| `automated` | Incidentes en los que se ha ejecutado un playbook |

Devuelve `502` `{"error": "..."}` y no procesa ninguna alerta si:

- el SIEM no está disponible o responde con otro error;
- falla el login con el Módulo 1 (Identidad), o está en espera tras un login rechazado (HU21);
- el SIEM responde `401` o `403`. Ante un `401` se renueva el token y se reintenta una sola vez.

## Errores no previstos

Cualquier error no previsto devuelve `500` `{"error":"internal_error"}` y se registra con traceback.
