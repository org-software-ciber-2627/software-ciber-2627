# Contrato SIEM: eventos y alertas reales

[OpenAPI](openapi.json) define la interfaz. [Acuerdo SEM-68](sem68-alert-query-contract.md) registra la aceptación del contrato de errores por Claudio. [README del módulo](../README.md) contiene arranque y comprobación reproducible.

## Ingesta

POST /events acepta un evento JSON con event_id, timestamp UTC terminado en Z, source, event_type, severity, title, description y details. Fuentes: ids, honeypot, scanner y pentesting. Severidades: low, medium, high y critical. Devuelve 200 con status success, message "Event received successfully" y event_id. Los cuerpos inválidos producen 400; un Content-Type incompatible, 415. event_id admite solo letras, dígitos, punto, guion bajo, dos puntos y guion (1-128 caracteres), lo que impide inyectar saltos de línea en los logs.

Un reintento idéntico (misma source y event_id, mismo contenido) devuelve 200 sin duplicar la alerta ni volver a notificarla. Un reenvío con la misma source y event_id pero contenido distinto devuelve 409 EVENT_CONFLICT y la alerta almacenada no se modifica. Un cuerpo mayor que siem.events.max-body-bytes (65536 por defecto, variable SIEM_EVENTS_MAX_BODY_BYTES) devuelve 413 PAYLOAD_TOO_LARGE, también en envíos chunked. Con el almacén lleno (siem.alerts.max-stored, 10000 por defecto, variable SIEM_ALERTS_MAX_STORED) las alertas nuevas devuelven 507 STORAGE_FULL.

| Grupo | source | Ejemplo de datos específicos en details |
| --- | --- | --- |
| G2 IDS | ids | `rule_id`, `source_ip`, `target_ip`, `protocol`, `distinct_ports_count`, `window_seconds` |
| G3 Honeypot | honeypot | `source_ip`, `service`, `username`, `credential`, `command` |
| G4 Escáner | scanner | `target`, `scan_id`, `tool`, `profile`, `script_id`, `evidence`, `cve`, `cvss` |
| G8 Pentesting | pentesting | `tool`, `target`, `instances`, `solution` |

Las alertas de pentesting tienen source_ip y target_ip null: G8 identifica el objetivo con una URL, que se conserva en details.target.

Esta rama genera y guarda una alerta en memoria por evento aceptado. No incorpora la persistencia de eventos de HU8 ni garantiza entrega externa de notificaciones.

## Consulta

GET /alerts devuelve {"alerts":[...]} con todas las alertas almacenadas, sin orden garantizado, filtros, paginación ni recortes. Vacío real: 200 con {"alerts":[]}. Un fallo nunca se representa como vacío.

Cada alerta incluye alert_id, event_id, timestamp, source, event_type, severity, title, description, source_ip, target_ip y details. Los campos IP pueden ser null; details conserva los atributos del productor. GET /alerts/{id} devuelve la misma alerta o 404 ALERT_NOT_FOUND si no existe.

Ambas consultas comparten errores {"error":{"code":"...","message":"..."}}:

| Estado | Código | Mensaje |
| --- | --- | --- |
| 503 | STORAGE_UNAVAILABLE | Alert storage is temporarily unavailable |
| 500 | INTERNAL_ERROR | An unexpected error occurred |

AlertErrorHandler aplica el acuerdo a ambas rutas. La indisponibilidad se representa mediante AlertStorageUnavailableException; los errores inesperados de ejecución reciben el 500 genérico. Los tests inyectan el fallo de almacenamiento porque el repositorio actual no tiene conexión externa. No se incluyen detalles internos.

## Compatibilidad y límites

Dashboard consume alerts y ordena/filtra en cliente; SOAR acepta el mismo contenedor. No se añaden status, priority, risk_score, recommended_action ni related_events. El almacenamiento es en memoria, se pierde al reiniciar y es común al listado y al detalle. Autenticación y persistencia duradera quedan fuera de este incremento.

Los ficheros mocks/alerts.json y contract/examples son datos de laboratorio para pruebas. El listado HTTP no consulta el mock. verify-contract.py comprueba las fixtures estáticas; smoke-test.py comprueba el servicio real mediante POST y consultas.

## Verificación y entrega

Desde modules/05-siem: `bash ./mvnw clean verify`. CI SIEM tests usa Java 21 y guarda los informes Surefire 14 días. [Evidencias HU16](../docs/hu16-acceptance.md).

Comunicación a G6/G7 prevista en Scrum de Scrums. La revisión por PR y aceptación final del PO se registran por separado de los tests.
