# Contrato del mock SIEM · Sprint 1 · SEM-6

Especificación del mock SIEM del Sprint 1. Describe la respuesta simulada y las alertas estáticas; no especifica la persistencia implementada en Sprint 2.

## Interfaz

| Método | Ruta | Respuesta |
| --- | --- | --- |
| GET | `/health` | 200 con `status: ok` y `module: 05-siem` |
| POST | `/events` | 200 para eventos válidos, 400 para cuerpos/eventos inválidos, 415 para un Content-Type incorrecto |
| GET | `/alerts` | 200 con `{"alerts": [...]}` |
| GET | `/alerts/{id}` | 200 con una alerta o 404 con `error.code: ALERT_NOT_FOUND` |

Acceso local `http://localhost:8005`; red Docker `http://siem:80`.

## Evento común

Un objeto JSON por petición, con `event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description` y `details`. Los textos comunes no pueden ser vacíos; `event_id` no exige UUID. `timestamp` termina en Z. `source` acepta `ids`, `honeypot` o `scanner`; `severity` acepta `low`, `medium`, `high` o `critical`. `details` es un objeto que conserva campos específicos y valores nulos. Las claves superiores desconocidas se rechazan.

| Grupo | Ejemplo de datos específicos |
| --- | --- |
| G2 IDS | `rule_id`, `source_ip`, `target_ip`, `protocol`, `distinct_ports_count`, `window_seconds` |
| G3 Honeypot | `source_ip`, `service`, `username`, `credential`, `command` |
| G4 Escáner | `target`, `scan_id`, `tool`, `profile`, `script_id`, `evidence`, `cve`, `cvss` |

La validación del mock comprueba la cabecera común y que `details` sea un objeto. La implementación de persistencia añade las reglas descritas en [SEM-65](sem65-ingestion-proposal.md).

## Acuse y errores

El 200/400 sigue lo comunicado a G3 y la historia SEM-10. El evento no se almacena ni genera una alerta. Los reintentos válidos también devuelven 200. El formato del acuse se ha conservado de la implementación de ingesta, con mensajes en inglés:

```json
{"status":"success","message":"Event received successfully (mock)","event_id":"HP-981839239323"}
```

Los errores siguen el formato común del borrador:

```json
{"error":{"code":"VALIDATION_ERROR","message":"The event does not match the required schema"}}
```

Códigos del mock: `INVALID_JSON`, `VALIDATION_ERROR`, `UNSUPPORTED_MEDIA_TYPE` y `ALERT_NOT_FOUND`. Los errores internos imprevistos no tienen un formato garantizado en esta versión.

## Alertas

Cada alerta conserva todos los campos del evento y añade `alert_id`, `source_ip` y `target_ip`. IDS toma las IP de `details`; Honeypot tiene destino null; Escáner tiene origen null y destino `details.target.ip`. El modelo de alerta no incluye `status`, `priority`, `risk_score`, `recommended_action` ni `related_events`.

`GET /alerts` utiliza `mocks/alerts.json`, con tres ejemplos completos. `GET /alerts/{id}` usa el identificador exacto, sensible a mayúsculas y minúsculas. El JSON estático no cambia después de POST /events.

Los ejemplos son datos simulados de laboratorio. `contract/openapi.json` conserva las respuestas del mock; consulta [SEM-65](sem65-ingestion-proposal.md) para el comportamiento de ingesta persistente.
