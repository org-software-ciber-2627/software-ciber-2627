# Integración Escáner → SIEM · Contrato de recepción de eventos

## Alcance y estado de implementación

Este contrato especifica la publicación de eventos del Escáner hacia `POST /events`: formato, identidad, severidad, destino, acuse y errores. Se reutilizan la ingesta común y la persistencia del SIEM; no se crea un endpoint específico por productor.

La referencia de persistencia es `cb27971d6ce59919f43bc3a824739de348ee1a16`. El comportamiento de almacenamiento se describe en [sem65-ingestion-proposal.md](sem65-ingestion-proposal.md). La referencia de formato del productor es el [parser del Escáner](https://github.com/org-software-ciber-2627/software-ciber-2627/blob/f04a1efd16fde000ddaee16711f00de86ee91b81/modules/04-escaner/src/parser.py). Estas referencias identifican versiones de código; no acreditan una ejecución de integración.

| Aspecto | Base de persistencia | Especificación de integración |
| --- | --- | --- |
| Ruta de recepción | `POST /events` | Se conserva |
| Identidad | `(source, event_id)` | Se conserva |
| Origen del Escáner | `scanner` | Se conserva |
| Severidades de eventos | `low`, `medium`, `high`, `critical` | `info`, `low`, `medium`, `high`, `critical` |
| Persistencia | PostgreSQL, perfil `persistence` | Se reutiliza sin transformar el evento |
| Alertas | Respuestas estáticas | Recibir un evento no genera una alerta |

**El soporte de `info` está implementado en esta rama.** La validación Java, el esquema JSON y OpenAPI admiten las cinco severidades. La base de datos debe utilizar los scripts actualizados o tener aplicada la migración `003-allow-info-severity.sql`. Una petición válida con `severity: "info"` devuelve 200 después de confirmar almacenamiento o un reenvío idéntico.

El [OpenAPI](openapi.json) describe la ingesta persistente y esta ampliación. El [ejemplo informativo](examples/grupo_4_scanner_info.json) forma parte de los ejemplos aceptados por el esquema de eventos. La incorporación de este contrato no acredita por sí sola un escaneo ni una publicación real del productor.

### Compatibilidad del publicador referenciado

El [publicador del Escáner en la versión referenciada](https://github.com/org-software-ciber-2627/software-ciber-2627/blob/f04a1efd16fde000ddaee16711f00de86ee91b81/modules/04-escaner/src/jobs.py) envía cada evento con `requests.post`, pero no inspecciona la respuesta HTTP ni el `event_id` del acuse y descarta las excepciones de publicación. Por tanto, esa versión no satisface los requisitos de observabilidad de entrega definidos aquí, aunque su parser ya utilice `scanner` y `details.target`.

Comprobar el acuse y hacer visibles los rechazos o fallos de conexión son responsabilidades del módulo productor. El SIEM no modifica ese publicador ni transforma sus eventos para ocultar incompatibilidades. La finalización del escaneo no debe presentarse como evidencia de una entrega confirmada; estos criterios necesitan una versión compatible y su prueba de integración.

## Petición y transporte

```http
POST /events
Content-Type: application/json
Accept: application/json
```

Cada petición contiene **un evento JSON**, sin envoltorio. No se envían arrays de eventos ni el informe completo de un escaneo. Un informe puede contener varios eventos y cada uno se publica por separado.

El destino se configura mediante `SIEM_URL`, incluyendo `/events`:

| Entorno | Ejemplo de destino | Condición |
| --- | --- | --- |
| Ambos procesos en el mismo equipo | `http://localhost:8005/events` | Puerto del SIEM configurado y accesible |
| Servicios dentro de la red Docker compartida | `http://siem:80/events` | Nombre y puerto del servicio SIEM accesibles en esa red |

`localhost` dentro del contenedor del Escáner identifica ese contenedor, no el SIEM. La variable del productor no activa el perfil de persistencia ni configura la base de datos del receptor.

Para confirmar almacenamiento, el SIEM necesita el perfil `persistence` y PostgreSQL disponible al arrancar. Sin el perfil, un evento válido recibe 503. El Compose de la base no activa automáticamente el perfil Java; la configuración se detalla en la [guía de persistencia](../docs/sem67-persistence-guide.md).

La API de esta base no implementa autenticación ni autorización de productores, y HTTP no aporta cifrado. Los eventos de prueba del Escáner utilizan datos ficticios y no contienen credenciales, tokens ni secretos reales. La conexión del SIEM a PostgreSQL sí utiliza una contraseña externa; el runner de pruebas genera una contraseña efímera para su base desechable.

## Formato del evento

Los ocho campos comunes son obligatorios y no se admiten propiedades adicionales en la raíz.

| Campo | Regla |
| --- | --- |
| `event_id` | String no vacío; identifica el evento dentro de `source`. UUID es válido, pero no obligatorio |
| `timestamp` | String con un instante ISO 8601 válido, en UTC y terminado en `Z` |
| `source` | Valor exacto `scanner` para el Escáner |
| `event_type` | String no vacío que expresa qué observación o hallazgo representa el evento |
| `severity` | Catálogo admitido: `info`, `low`, `medium`, `high`, `critical` |
| `title` | String no vacío |
| `description` | String no vacío |
| `details` | Objeto JSON con los atributos del productor; conserva objetos, listas, booleanos, números y nulos |

Las severidades son valores exactos, en minúsculas. El nuevo valor es una ampliación del catálogo común de eventos, no un alias ni una excepción de deserialización exclusiva para el Escáner. Los valores desconocidos se rechazan.

Los datos deben poder representarse en PostgreSQL. Caracteres nulos, Unicode incompleto, timestamps o números fuera del rango de almacenamiento se rechazan; no se sustituyen ni truncan silenciosamente. Véase la [semántica de ingesta persistente](sem65-ingestion-proposal.md).

### Atributos del Escáner

El destino observado se representa dentro de `details.target`, nunca como una propiedad raíz del evento.

| Atributo | Contenido |
| --- | --- |
| `details.target` | Contexto del destino: `ip`, `port`, `protocol` y `service` |
| `details.scan_id` | Identificador del escaneo que produjo el evento; no sustituye a `event_id` |
| `details.tool` | Herramienta utilizada, por ejemplo `nmap` |
| `details.profile` | Perfil del escaneo |
| `details.script_id` | Script asociado, o `null` cuando no aplica |
| `details.evidence` | Evidencia textual, o `null` cuando no aplica |
| `details.cve` | Referencia CVE, o `null` cuando no se dispone de ella |
| `details.cvss` | Puntuación CVSS, o `null` cuando no se dispone de ella |

Este perfil describe los atributos que publica el Escáner. El validador común exige que `details` sea un objeto, pero no impone un esquema interno específico por productor. Un atributo descrito aquí no se convierte automáticamente en una validación Java nueva. Los valores nulos no se sustituyen por strings como `"null"`.

## Tipos de evento y severidad

| Tipo observado | Significado | Tratamiento de severidad |
| --- | --- | --- |
| `port_open` | Observación de un puerto abierto | `info` para inventario, sin afirmar una vulnerabilidad por ese hecho aislado |
| `service_detected` | Identificación de un servicio | `info` para inventario |
| `cve_detected` | Hallazgo asociado a una referencia CVE | Severidad no informativa asignada por el productor según el hallazgo |
| `vulnerability_detected` | Hallazgo de vulnerabilidad sin referencia CVE obligatoria | Severidad no informativa asignada por el productor según el hallazgo |

`info` significa **observación informativa que, por sí sola, no expresa una vulnerabilidad ni implica generar una alerta**. No se convierte en `low`, no significa que un activo sea seguro y no sustituye una severidad desconocida o ausente.

El catálogo de tipos de esta tabla documenta la integración; la validación común de `event_type` continúa admitiendo un string no vacío. No se añaden en esta ampliación reglas automáticas que calculen severidad a partir de CVSS o de `event_type`. La clasificación corresponde al productor y el SIEM conserva el valor recibido cuando cumple el contrato.

La incorporación de `info` afecta a eventos de entrada y almacenamiento. No amplía automáticamente el catálogo del modelo público de alertas, no cambia la correlación y no convierte todas las observaciones del escáner en incidentes. Los consumidores de eventos deben contemplar el nuevo valor; las interfaces de alertas conservan su contrato mientras no se especifique otra ampliación.

## Ejemplo informativo

Ejemplo aceptado por el contrato de eventos de esta rama. La dirección es un marcador saneado y no un objetivo ejecutable.

```json
{
  "event_id": "SCAN-INFO-EXAMPLE-001",
  "timestamp": "2026-09-29T10:30:00Z",
  "source": "scanner",
  "event_type": "service_detected",
  "severity": "info",
  "title": "Service detected: http",
  "description": "HTTP service detected on TCP port 80.",
  "details": {
    "target": {
      "ip": "192.168.X.X",
      "port": 80,
      "protocol": "tcp",
      "service": "http"
    },
    "scan_id": "SCAN-EXAMPLE-001",
    "tool": "nmap",
    "profile": "web",
    "script_id": null,
    "evidence": null,
    "cve": null,
    "cvss": null
  }
}
```

El [ejemplo de vulnerabilidad existente](examples/grupo_4_scanner.json) utiliza `scanner`, `details.target` y `medium`; ya corresponde al catálogo de severidades de la base. Ambos tipos de evento comparten la misma ruta de recepción y el mismo contenedor de respuesta.

## Identidad, acuse y reenvíos

La identidad es `(source, event_id)`. El productor genera el identificador para el evento y conserva ese identificador, timestamp y contenido cuando reenvía exactamente ese evento. Dos fuentes pueden utilizar el mismo `event_id` sin representar el mismo evento. Un nuevo escaneo puede producir eventos con nuevas identidades.

HTTP 200 confirma almacenamiento o reconocimiento de un reenvío idéntico:

```json
{
  "status": "success",
  "message": "Event stored successfully",
  "event_id": "SCAN-INFO-EXAMPLE-001"
}
```

El productor debe comprobar el estado HTTP y que `event_id` coincide con el enviado. Un 200 del endpoint que inicia el escaneo, un estado de escaneo terminado o un `/health` correcto no acreditan por sí solos la publicación al SIEM.

Un reenvío con la misma identidad y contenido devuelve 200 sin insertar otra fila. La misma identidad con contenido distinto devuelve 409 y conserva el original. Los textos, incluido el timestamp original cuando está disponible, se comparan exactamente. JSONB compara valores y estructura: no conserva necesariamente orden de claves ni la representación textual original de números; el orden de arrays sí es significativo.

No se define una política de reintentos automáticos ni se promete entrega exactamente una vez. Un timeout o una conexión interrumpida no demuestran que el servidor no haya almacenado el evento. Si se reenvía, se debe preservar su identidad y contenido; un 200 tampoco acredita generación de alertas.

## Errores y observabilidad de entrega

| Situación | HTTP | Código | Conducta esperada del productor |
| --- | --- | --- | --- |
| Evento almacenado o reenvío idéntico | 200 | No aplica | Comprobar acuse y coincidencia de `event_id` |
| JSON mal formado o estructura incompatible | 400 | `INVALID_JSON` | Hacer visible el rechazo; no tratarlo como entrega correcta |
| Evento inválido, severidad desconocida o datos no almacenables | 400 | `VALIDATION_ERROR` | Corregir el dato o el formato antes de volver a publicar |
| Misma identidad con contenido diferente | 409 | `EVENT_ID_CONFLICT` | Registrar el conflicto sin sobrescribir el evento original |
| Tipo de contenido no admitido | 415 | `UNSUPPORTED_MEDIA_TYPE` | Utilizar `application/json` |
| Persistencia desactivada o almacenamiento inaccesible durante la petición | 503 | `STORAGE_UNAVAILABLE` | Mostrar fallo de entrega; no confundirlo con un escaneo sin hallazgos |
| Timeout o error de conexión | Sin respuesta HTTP garantizada | No aplica | Mostrar resultado de entrega desconocido o fallido, sin afirmar que el evento no se almacenó |

Los errores conservan el contenedor común:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The event does not match the required schema"
  }
}
```

El productor debe distinguir el resultado del escaneo del resultado de publicación. No debe descartar silenciosamente respuestas 400/409/415/503 ni errores de conexión. Los registros de diagnóstico no deben incluir secretos ni cuerpos completos con información sensible.

El estado HTTP es el resultado de la petición, no un campo nuevo que deba añadirse al evento. Si PostgreSQL impide arrancar la aplicación con el perfil activo, no existe una respuesta HTTP del SIEM; es un fallo de disponibilidad de arranque.

## Compatibilidad y despliegue de la ampliación

El soporte de `info` alinea el esquema JSON, OpenAPI, validación Java y restricción SQL de eventos. La ampliación conserva las cuatro severidades anteriores y no cambia la identidad ni los ocho campos comunes.

Una instalación nueva necesita una definición SQL compatible. Una base existente necesita una migración que conserve los datos; los scripts de inicialización de Docker no vuelven a aplicarse automáticamente sobre un volumen ya creado. No debe habilitarse el envío de `info` contra una base que todavía lo rechaza.

La actualización del catálogo de eventos se comunica a sus consumidores. No se normaliza en el SIEM `vulnerability_scanner` a `scanner`, no se mueve un `target` raíz y no se sustituye `info` por `low`: el productor envía el formato descrito.

## Criterios verificables de integración

| Caso | Resultado exigido |
| --- | --- |
| Evento de vulnerabilidad con severidad ya admitida | 200, mismo `event_id` y fila persistida fielmente |
| Evento `service_detected` o `port_open` con `info` y esquema SQL actualizado | 200 y severidad `info` conservada |
| Propiedad `target` en la raíz | 400 sin inserción |
| `source: vulnerability_scanner` | 400 sin inserción |
| Severidad desconocida, fecha inválida o informe completo en lugar de un evento | 400 sin inserción |
| Campos anidados y valores nulos | Conservados al almacenar y recuperar |
| Reenvío idéntico | 200 y una única fila por identidad |
| Reenvío con contenido distinto | 409 y evento original intacto |
| Escaneo real en laboratorio | Evento generado, publicación y almacenamiento correlacionados por `event_id` y versión |
| SIEM inaccesible o rechazo del envío | Fallo o resultado incierto observable, separado del estado de escaneo |
| Migración desde la restricción antigua | Datos anteriores conservados, `info` admitido y valores desconocidos rechazados |
| Fin de las pruebas | Procesos de prueba terminados, recursos desechables retirados y puertos comprobados |

Un JSON preparado valida compatibilidad, pero no acredita por sí solo un escaneo real. Un evento de inventario no sustituye al hallazgo de vulnerabilidad en la prueba de extremo a extremo. Las pruebas locales de compatibilidad del SIEM se describen en [scanner-events-tests.md](../docs/scanner-events-tests.md). No equivalen a ejecutar el Escáner ni a verificar su publicador real.
