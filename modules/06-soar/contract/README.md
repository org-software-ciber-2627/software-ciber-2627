# Contrato de API

## `GET /health`

Devuelve `200`:

```json
{"status":"ok","module":"06-soar"}
```

## `GET /incidents`

Devuelve `200` con una lista de incidentes registrados. Cada elemento contiene
`id`, `alert_key`, `alert` y `first_seen`, y desde el Sprint 2 también:

| Campo | Descripción |
|---|---|
| `incident_id` | Identificador del incidente normalizado (`INC-XXXXXX`) |
| `priority` | Prioridad calculada (HU5) |
| `status` | Estado del incidente (HU6) |
| `automation` | `{"automatable", "playbook", "reason"}` (HU13) |
| `responses` | Respuestas ejecutadas (HU15) |

Las filas guardadas antes del Sprint 2 devuelven estos campos a `null` y `responses` vacío.

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
