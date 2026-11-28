# Contrato de API

## `GET /health`

Devuelve `200`:

```json
{"status":"ok","module":"06-soar"}
```

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

### Regla de `applied_playbook`

- Vale el nombre del playbook (campo `playbook` de sus respuestas ejecutadas, hoy `"brute_force"`)
  si el incidente tiene **al menos una** respuesta registrada, **sea cual sea su `status`**
  (`success`, `failed` o `skipped`).
- Vale `null` si el incidente no tiene ninguna respuesta.
- `applied_playbook` **no** indica si la respuesta tuvo éxito: el resultado de cada acción está en
  `responses[].status`, y el motivo en `responses[].message` (éxito) o `responses[].error` (fallo u omisión).

### Ejemplo: incidente automatizado (`notify` en `skipped`)

Respuesta real con `GROUP7_NOTIFY_URL` sin configurar. Como ninguna acción tuvo éxito, el incidente sigue en `open`.

```json
{
  "id": 2,
  "alert_key": "SIEM-ALERT-EJEMPLO-002",
  "alert": {
    "alert_id": "SIEM-ALERT-EJEMPLO-002",
    "description": "El honeypot ha registrado un evento clasificado como fuerza bruta sobre SSH.",
    "details": {
      "command": null,
      "credential": "123456",
      "service": "ssh",
      "source_ip": "192.168.1.50",
      "username": "root"
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
  "status": "open",
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
        "playbook_status": "FAILED"
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

## `POST /incidents/{incident_id}/status`

Cambia el estado del incidente según HU6 (ver `status.md`). Cuerpo:

```json
{"status":"closed","justification":"Revisado por el analista","resolution_reason":"IP bloqueada"}
```

- `200` con el incidente actualizado. Al cerrar, `resolved_at` se rellena.
- `400` `{"error":"..."}` si el cuerpo no es válido o HU6 rechaza el cambio.
- `404` `{"error":"incident_not_found"}` si el incidente no existe.

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

Si el SIEM no está disponible devuelve `502`.

## Errores no previstos

Cualquier error no previsto devuelve `500` `{"error":"internal_error"}` y se registra con traceback.
