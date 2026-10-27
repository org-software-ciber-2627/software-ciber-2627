# Equipo 5 · SIEM · Sprint 1

Candidato de integración de SEM-5, SEM-6, SEM-10 y SEM-20. Conserva el trabajo de las cuatro ramas y añade correcciones y pruebas. Requiere revisión cruzada y aceptación del PO.

## Alcance

Servidor Java 21 y Spring Boot 4.1.1. Recibe un evento JSON por petición, valida la cabecera común y devuelve un acuse. Publica tres alertas estáticas, una por productor, conservando todos sus campos y valores nulos.

No hay persistencia, deduplicación, correlación ni autenticación real en este mock. Enviar eventos no cambia la lista de alertas. El contrato de G1 y la integración externa siguen pendientes.

## Arranque con Docker

Desde la raíz del repositorio:

```bash
docker compose up --build -d siem
docker compose ps siem
curl -f http://localhost:8005/health
```

Dirección local: `http://localhost:8005`. Entre contenedores de la red `ciberurjc`: `http://siem:80`. El Dockerfile mantiene el puerto interno 80 y el healthcheck del compose compartido.

Para detener el módulo:

```bash
docker compose stop siem
```

## Arranque local con Java

Requiere Java 21 o posterior. Desde `modules/05-siem`:

```bash
./mvnw spring-boot:run
```

El puerto local por defecto es 8005. Puede configurarse con `SERVER_PORT`. El wrapper descarga Maven y las dependencias oficiales en el primer arranque.

## API del mock

| Ruta | Resultado |
| --- | --- |
| `GET /health` | 200, `{"status":"ok","module":"05-siem"}` |
| `POST /events` | 200 y acuse si el evento es válido; 400 si el cuerpo o sus campos son inválidos; 415 para un Content-Type distinto de JSON |
| `GET /alerts` | 200, `{"alerts":[...]}` con tres ejemplos |
| `GET /alerts/{id}` | 200 con una alerta; 404 con error JSON si no existe |

Se usa el 200/400 ya comunicado a G3. El borrador anterior proponía 201/422 y deduplicación; esta rama los sustituye para el mock del Sprint 1. La ratificación del contrato entre equipos y del formato del acuse sigue pendiente.

```bash
curl -i -H 'Content-Type: application/json' --data-binary @modules/05-siem/contract/examples/grupo_3_honeypot.json http://localhost:8005/events
curl -i http://localhost:8005/alerts
curl -i http://localhost:8005/alerts/SIEM-ALERT-EJEMPLO-003
```

## Errores de POST /events (SEM-24 · HU7)

IDS, Honeypot, Escáner e Identidad deben enviar un único objeto de evento por petición con `Content-Type: application/json`. Los rechazos descritos aquí devuelven JSON con un objeto `error` que contiene únicamente `code` y `message`. No se añade una propiedad `details` a la respuesta de error; `details` sigue siendo un campo del evento de entrada.

| HTTP | `error.code` | Motivo del rechazo |
| --- | --- | --- |
| 400 | `INVALID_JSON` | No se puede leer o convertir el cuerpo: JSON mal formado, cuerpo obligatorio ausente, estructura incompatible, tipos incorrectos o propiedades superiores desconocidas. El JSON puede ser sintácticamente correcto y aun así producir este código. |
| 400 | `VALIDATION_ERROR` | El objeto se ha podido convertir, pero incumple restricciones: campos obligatorios ausentes o nulos, textos en blanco, valores fuera de catálogo o `timestamp` incorrecto. |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | El `Content-Type` es incompatible con `application/json`, por ejemplo `text/plain` o `application/xml`. |

`error.code` identifica la categoría y `error.message` explica el motivo en inglés. El productor debe utilizar el estado HTTP y el código para clasificar el rechazo, y el mensaje para corregirlo. Los ejemplos genéricos de [OpenAPI](contract/openapi.json) conservan su validez: los mensajes detallados mantienen el mismo formato y los mismos códigos.

### Reglas que debe cumplir el evento

- Los ocho campos son obligatorios y no pueden ser `null`: `event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description` y `details`.
- Todos excepto `details` deben ser cadenas JSON. No se convierten números ni booleanos automáticamente en texto.
- `event_id`, `timestamp`, `event_type`, `title` y `description` no pueden estar vacíos ni contener solo espacios en blanco. `event_id` no exige UUID; `event_type` no tiene todavía un catálogo cerrado.
- `source` admite exactamente `ids`, `honeypot`, `scanner` o `identity`.
- `severity` admite exactamente `low`, `medium`, `high` o `critical`. Los catálogos distinguen mayúsculas y no admiten espacios adicionales.
- `timestamp` debe representar una fecha y hora UTC válidas y terminar en `Z`, por ejemplo `2026-09-22T18:30:15Z`. Una fecha con `+00:00` también se rechaza por no usar el sufijo exigido.
- `details` debe ser un objeto JSON. Puede estar vacío y contener propiedades propias del productor y valores nulos internos; todavía no se validan sus reglas internas.
- No se admiten propiedades adicionales en el objeto principal del evento.

La validación se realiza en orden mediante Jackson (lectura y conversión), Bean Validation (restricciones de `Event`) y `EventService` (fecha). El servidor no ejecuta directamente [event-schema.json](contract/event-schema.json) para cada petición; ese archivo describe el contrato de entrada.

### Ejemplo: tipo de dato incorrecto

Petición `POST /events` con `Content-Type: application/json` y este cuerpo:

```json
{
  "event_id": 42,
  "timestamp": "2026-09-22T18:30:15Z",
  "source": "honeypot",
  "event_type": "fuerza_bruta",
  "severity": "medium",
  "title": "Intento de fuerza bruta",
  "description": "Intento detectado sobre SSH",
  "details": {}
}
```

Respuesta **HTTP 400**:

```json
{
  "error": {
    "code": "INVALID_JSON",
    "message": "event_id: must be a string"
  }
}
```

Corrección: enviar el identificador como cadena, por ejemplo `"event_id": "42"`.

### Ejemplo: varios campos incorrectos

Petición `POST /events` con `Content-Type: application/json` y este cuerpo:

```json
{
  "event_id": "HP-981839239323",
  "timestamp": "2026-09-22T18:30:15Z",
  "source": "soar",
  "event_type": "fuerza_bruta",
  "severity": "urgent",
  "title": " ",
  "description": null,
  "details": {}
}
```

Respuesta **HTTP 400**:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "description: is required and must not be blank; severity: must be one of: low, medium, high, critical; source: must be one of: ids, honeypot, scanner, identity; title: is required and must not be blank"
  }
}
```

Cada fragmento identifica un campo y su motivo; los campos se separan con `; `. Aparecen en orden alfabético, independientemente del orden de las propiedades enviadas. Cada campo aparece una vez y no se repiten mensajes idénticos dentro de él. En este caso, el productor debe rellenar `description` y `title`, usar `source: "honeypot"` y elegir una severidad del catálogo según el evento.

### Otros rechazos y mensajes exactos

En las filas que modifican un campo, partir del [evento válido de Honeypot](contract/examples/grupo_3_honeypot.json) y aplicar solo el cambio indicado. Todas las peticiones son `POST /events` con `Content-Type: application/json`, salvo la última fila. Las respuestas utilizan siempre el objeto `error` mostrado arriba.

| Petición inválida | HTTP / `error.code` | `error.message` exacto |
| --- | --- | --- |
| Omitir `title`, enviarlo como `null`, `""` o `" "` | 400 / `VALIDATION_ERROR` | `title: is required and must not be blank` |
| Enviar `details: null` | 400 / `VALIDATION_ERROR` | `details: is required and must be a JSON object` |
| Enviar `details: 42` | 400 / `INVALID_JSON` | `details: must be a JSON object` |
| Añadir `source_module: "honeypot"` al objeto principal | 400 / `INVALID_JSON` | `The event contains an unknown field; allowed fields are: event_id, timestamp, source, event_type, severity, title, description, details` |
| Enviar como cuerpo completo únicamente `{` | 400 / `INVALID_JSON` | `Malformed JSON: check the request body syntax` |
| Enviar un cuerpo vacío, solo espacios o el literal `null` | 400 / `INVALID_JSON` | `The request body is required and must contain a JSON event object` |
| Enviar como cuerpo completo `[]` | 400 / `INVALID_JSON` | `The body must match the JSON event structure; expected a single event object with correctly typed fields` |
| Enviar `timestamp: "2026-09-22T18:30:15+00:00"` | 400 / `VALIDATION_ERROR` | `timestamp: must end with Z (UTC)` |
| Enviar `timestamp: "2026-02-30T18:30:15Z"` | 400 / `VALIDATION_ERROR` | `timestamp: must represent a valid UTC date-time` |
| Enviar el evento válido con `Content-Type: text/plain` | 415 / `UNSUPPORTED_MEDIA_TYPE` | `Content-Type must be application/json` |

### Cómo corregir y reenviar

1. Leer el estado HTTP, `error.code` y `error.message`.
2. Para `INVALID_JSON`, revisar sintaxis, cuerpo, estructura, tipos y nombres de campos. Para `VALIDATION_ERROR`, corregir los campos indicados según las reglas anteriores. Para HTTP 415, enviar JSON con `Content-Type: application/json`.
3. Reenviar el evento completo corregido. Repetir la misma petición inválida no resolverá el rechazo. Un evento válido conserva la respuesta HTTP 200 con el acuse del mock.

Los mensajes no incluyen valores del evento, trazas ni mensajes internos de Jackson. Solo se muestran nombres de campos definidos en el modelo `Event`. Los nombres desconocidos y las claves internas de `details` no se reproducen, ya que también pueden contener información sensible. Ante una propiedad superior desconocida, se enumeran los campos permitidos para que el productor compare los nombres y corrija su petición. Esto no cambia la aceptación de propiedades propias dentro de `details`.

El cuerpo vacío y el literal JSON `null` se detectan mediante `RequestBodyAdvice`, limitado al controlador de eventos, sin depender del texto interno de las excepciones de Spring. Los fallos de conversión de Jackson se distinguen de los de sintaxis cuando la excepción lo permite; no se devuelve su mensaje interno.

Bean Validation puede informar de varios campos incorrectos en una respuesta. Los errores de conversión JSON pueden detenerse en el primer fallo detectado y las etapas posteriores no se ejecutan si falla una anterior. Por eso, después de corregir un error puede aparecer otro; las comprobaciones de fecha del servicio solo se realizan cuando pasa Bean Validation. Un campo ausente y uno enviado como `null` pueden compartir el mismo mensaje.

Los mensajes y el formato de estos ejemplos están comprobados en [SiemHttpIntegrationTests.java](src/test/java/com/ciberurjc/siem/SiemHttpIntegrationTests.java), incluidos el orden de errores, el HTTP 415 y la ausencia de valores sensibles en las respuestas.

## Contrato y comprobaciones

- `contract/openapi.json`: interfaz del mock preparada para revisión.
- `contract/event-schema.json`: esquema local del SIEM. No sustituye el esquema global pendiente de acuerdo.
- `contract/examples/`: ejemplos G2, G3 y G4.
- `mocks/alerts.json`: fuente única de las tres alertas, incluida en el JAR.

Desde `modules/05-siem`:

```bash
./mvnw clean verify
```

Las pruebas arrancan el servidor en un puerto aleatorio y comprueban los cuatro orígenes admitidos, los campos obligatorios, valores inválidos, JSON incorrecto, los mensajes detallados de rechazo, el HTTP 415, los tres detalles de alerta y el error 404. También verifican el formato de error, su orden estable y que no revele valores sensibles. No certifican servicios de otros equipos.

Consultar `docs/estado-integracion.md` para evidencias y acuerdos pendientes. La API no expone credenciales en los logs; los datos de `credential` de los ejemplos son datos ficticios de laboratorio.

Comprobación del contenedor arrancado, desde la raíz del repositorio:

```bash
python3 modules/05-siem/scripts/smoke-test.py http://localhost:8005
```

Validación del contrato local. Requiere `jsonschema>=4,<5` en un entorno Python:

```bash
python3 modules/05-siem/scripts/verify-contract.py
```
