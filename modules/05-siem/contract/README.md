# Contrato SIEM · Sprint 2

Especificación de la rama actual: ingesta persistente de HU8, histórico de HU10 y alertas estáticas. [openapi.json](openapi.json) es el contrato de referencia; [history-events.md](history-events.md) detalla navegación, errores y límites del histórico. No implementa autenticación ni autorización.

## Interfaz

| Método | Ruta | Respuesta |
| --- | --- | --- |
| GET | `/health` | 200 con `status: ok` y `module: 05-siem` |
| POST | `/events` | 200 al guardar/reconocer reenvío; 400 inválido; 409 conflicto; 415 tipo incorrecto; 503 sin almacenamiento |
| GET | `/events` | 200 con `events`, `next_offset`, `next`; 400 consulta inválida; 503 indisponibilidad/timeout; 500 error inesperado |
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

La validación común comprueba la cabecera común y que `details` sea un objeto. La implementación de persistencia añade las reglas descritas en [SEM-65](sem65-ingestion-proposal.md).

## Acuse y errores

Con el perfil `persistence`, POST confirma 200 después de almacenar o reconocer un reenvío idéntico. Misma clave `(source, event_id)` con otro contenido produce 409. Sin perfil o con almacenamiento inaccesible durante la petición responde 503. Con persistencia activa, PostgreSQL debe estar disponible al arrancar. No genera alertas. El acuse utiliza mensajes en inglés:

```json
{"status":"success","message":"Event stored successfully","event_id":"HP-981839239323"}
```

Los errores usan el siguiente formato:

```json
{"error":{"code":"VALIDATION_ERROR","message":"The event does not match the required schema"}}
```

Códigos de ingesta: `INVALID_JSON`, `VALIDATION_ERROR`, `UNSUPPORTED_MEDIA_TYPE`, `EVENT_ID_CONFLICT` y `STORAGE_UNAVAILABLE`. El histórico usa `VALIDATION_ERROR`, `STORAGE_UNAVAILABLE` e `INTERNAL_ERROR` y devuelve `Cache-Control: no-store` en éxito y errores gestionados. Las alertas conservan `ALERT_NOT_FOUND`.

## Alertas

Cada alerta conserva todos los campos del evento y añade `alert_id`, `source_ip` y `target_ip`. IDS toma las IP de `details`; Honeypot tiene destino null; Escáner tiene origen null y destino `details.target.ip`. El modelo de alerta no incluye `status`, `priority`, `risk_score`, `recommended_action` ni `related_events`.

`GET /alerts` utiliza `mocks/alerts.json`, con tres ejemplos completos. `GET /alerts/{id}` usa el identificador exacto, sensible a mayúsculas y minúsculas. El JSON estático no cambia después de POST /events.

Los ejemplos son datos simulados de laboratorio. El comportamiento de ingesta se detalla en [SEM-65](sem65-ingestion-proposal.md); HU10 solo actualiza su descripción en OpenAPI, sin cambiar POST. La [matriz de pruebas del histórico](../docs/history-events-tests.md) identifica ejecución y límites. Las versiones históricas del contrato permanecen en Git.
