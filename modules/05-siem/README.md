# Equipo 5 · SIEM · Alertas reales

Esta rama integra la generación y el almacén en memoria de HU13, el listado de HU16 y el detalle de HU17. POST /events valida el evento, genera su alerta y la guarda; GET /alerts y GET /alerts/{id} consultan el mismo repositorio.

## Ejecutar y comprobar

Requiere Java 21 o posterior. Desde modules/05-siem:

```bash
bash ./mvnw --batch-mode --no-transfer-progress clean verify
bash ./mvnw spring-boot:run
```

El puerto por defecto es 8005, configurable mediante SERVER_PORT. Con una instancia recién arrancada, sin datos:

```bash
curl -i http://localhost:8005/alerts
```

Resultado: 200 y {"alerts":[]}. Desde la raíz del repositorio:

```bash
curl -i -H 'Content-Type: application/json' --data-binary @modules/05-siem/contract/examples/grupo_2_ids_ejemplo_propuesto.json http://localhost:8005/events
curl -i http://localhost:8005/alerts
python3 modules/05-siem/scripts/smoke-test.py http://localhost:8005
```

El script envía los ejemplos de los productores (G2 IDS, G3 Honeypot, G4 Escáner y G8 Pentesting en contract/examples), comprueba que aparecen en el listado y que el detalle coincide. Modifica el almacén de la instancia indicada; usar una instancia de desarrollo. No presupone que el almacén esté vacío ni identifica las alertas por posición.

## API

| Ruta | Resultado |
| --- | --- |
| GET /health | 200, status ok y module 05-siem |
| POST /events | 200 con acuse (también en reintento idéntico); 400 para evento inválido; 409 EVENT_CONFLICT si se reenvía el mismo source y event_id con otro contenido; 413 PAYLOAD_TOO_LARGE; 415 para tipo de contenido incorrecto; 507 STORAGE_FULL |
| GET /alerts | 200 con alerts: array completo; vacío si no hay alertas |
| GET /alerts/{id} | 200 con la alerta; 404 ALERT_NOT_FOUND si no existe |
| Ambas consultas de alertas | 503 STORAGE_UNAVAILABLE para indisponibilidad identificada; 500 INTERNAL_ERROR para fallo inesperado |

Los errores usan {"error":{"code":"...","message":"..."}}. El 500 dice "An unexpected error occurred", sin detalles internos. El 503 se prueba con un fallo tipado inyectado: el repositorio en memoria no tiene una conexión externa que pueda caerse.

Los once campos son alert_id, event_id, timestamp, source, event_type, severity, title, description, source_ip, target_ip y details. Las IP pueden ser null. No hay filtros, paginación, truncado ni orden garantizado. Las alertas de mocks/alerts.json son fixtures de pruebas, no la fuente del listado.

## Alcance y límites

Las alertas se pierden al reiniciar. La rama todavía no incorpora HU8 de persistencia de eventos. Cada evento aceptado produce una alerta; no se implementan aquí nuevas reglas de correlación. Un reintento idéntico no duplica la alerta ni la vuelve a notificar; un reenvío con contenido distinto se rechaza con 409 y no modifica la alerta guardada. No se acredita entrega externa de notificaciones a SOAR ni autenticación real.

El detalle de Claudio se integra como dependencia; los errores comunes se aplican mediante AlertErrorHandler. La interfaz antigua repositories.AlertRepository permanece sin uso y no es el almacén activo.

## Contrato, CI y aceptación

- [OpenAPI](contract/openapi.json): formato del listado, detalle y errores.
- [Acuerdo SEM-68](contract/sem68-alert-query-contract.md).
- [Evidencias y aceptación HU16](docs/hu16-acceptance.md).
- Workflow SIEM tests: Java 21, Maven clean verify e informes Surefire durante 14 días. Las pruebas locales no sustituyen CI ni aceptación del PO.

Con Docker, desde la raíz: `docker compose up --build -d siem`. El puerto publicado es 8005 y el interno 80. La comprobación de esta entrega se ejecuta localmente con Java; el funcionamiento global de Docker depende de la CI compartida.
