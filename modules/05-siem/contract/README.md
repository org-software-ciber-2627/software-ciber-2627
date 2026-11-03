# Contrato del mock SIEM · Sprint 1 · SEM-6

Versión `0.2.0-sprint1-review`. Candidato de integración pendiente de ratificación intergrupo, revisión cruzada y aceptación del PO.

## Interfaz

| Método | Ruta | Respuesta |
| --- | --- | --- |
| GET | `/health` | 200 con `status: ok` y `module: 05-siem` |
| POST | `/events` | 200 para eventos válidos, 400 para cuerpos/eventos inválidos, 415 para un Content-Type incorrecto |
| GET | `/alerts` | 200 con `{"alerts": [...]}` |
| GET | `/alerts/{id}` | 200 con una alerta o 404 con `error.code: ALERT_NOT_FOUND` |

Acceso local `http://localhost:8005`; red Docker `http://siem:80`.

## Evento común

Un objeto JSON por petición, con `event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description` y `details`. Los textos comunes no pueden ser vacíos; `event_id` no exige UUID. `timestamp` es una fecha válida UTC terminada en Z. `source` acepta `ids`, `honeypot` o `scanner`; `severity` acepta `low`, `medium`, `high` o `critical`. `details` es un objeto que conserva campos específicos y valores nulos. Las claves superiores desconocidas se rechazan en este candidato; ratificar esta política con los productores.

| Grupo | Ejemplo de datos específicos |
| --- | --- |
| G2 IDS | `rule_id`, `source_ip`, `target_ip`, `protocol`, `distinct_ports_count`, `window_seconds` |
| G3 Honeypot | `source_ip`, `service`, `username`, `credential`, `command` |
| G4 Escáner | `target`, `scan_id`, `tool`, `profile`, `script_id`, `evidence`, `cve`, `cvss` |

La validación de Sprint 1 comprueba la cabecera y que `details` sea un objeto. Reglas internas por productor y catálogo de `event_type` requieren acuerdo antes del servicio real.

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

## Alertas para G6 y G7

Cada alerta conserva todos los campos del evento y añade `alert_id`, `source_ip` y `target_ip`. IDS toma las IP de `details`; Honeypot tiene destino null; Escáner tiene origen null y destino `details.target.ip`. No añadir `status`, `priority`, `risk_score`, `recommended_action` ni `related_events` sin acuerdo.

`GET /alerts` utiliza `mocks/alerts.json`, con tres ejemplos completos. `GET /alerts/{id}` usa el identificador exacto, sensible a mayúsculas y minúsculas. El JSON estático no cambia después de POST /events.

## Acuerdos pendientes

- Ratificar respuestas, formato del acuse, claves extra y catálogos con G2/G3/G4/G6/G7.
- Confirmar que G6/G7 consultan mediante GET, y verificarlo contra sus servicios.
- Negociar con G1 el formato de credenciales y los roles de cada endpoint.
- Revisar el esquema local y coordinar su adopción en `shared/event-schema.json`, mantenido fuera de esta propuesta del módulo.
- Definir persistencia, deduplicación y correlación en las historias posteriores. El borrador 0.1.0 propuso 201/422/409; no son respuestas del mock actual.

Los ejemplos son simulados de laboratorio. Su presencia, las pruebas locales y el contrato no sustituyen el acuerdo entre equipos ni la aprobación del PR.
