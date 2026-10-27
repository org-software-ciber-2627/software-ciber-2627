# Ingesta persistente de eventos

Este documento describe el comportamiento de la implementación de persistencia. El OpenAPI y el README de esta carpeta conservan el contrato histórico del mock Sprint 1.

No cambia el cuerpo de los productores ni los valores de `source`: `ids`, `honeypot`, `scanner`. Se mantienen los errores de validación existentes (400/415) y las alertas estáticas.

| Situación | Respuesta propuesta |
| --- | --- |
| Evento válido guardado por primera vez | 200 tras confirmar la inserción |
| Mismo `(source, event_id)` y contenido idéntico | 200, sin insertar ni sobrescribir |
| Mismo `(source, event_id)` con contenido distinto | 409 `EVENT_ID_CONFLICT`, conservando el original |
| Perfil `persistence` desactivado o fallo del almacenamiento durante la petición | 503 `STORAGE_UNAVAILABLE` |

Los datos que PostgreSQL no puede representar reciben 400 `VALIDATION_ERROR` sin insertar la petición: caracteres nulos, Unicode incompleto y fechas o números fuera del rango de almacenamiento. El parser puede rechazar antes algunos valores con 400 `INVALID_JSON`. No se sustituyen caracteres silenciosamente. Este comportamiento no modifica el OpenAPI histórico ni añade fuentes o campos al contrato.

El acuse es el mismo para una inserción y un reenvío idéntico:

```json
{"status":"success","message":"Event stored successfully","event_id":"HP-981839239323"}
```

Los errores nuevos conservan el contenedor `error` existente:

```json
{"error":{"code":"EVENT_ID_CONFLICT","message":"The event identifier already belongs to different content"}}
```

```json
{"error":{"code":"STORAGE_UNAVAILABLE","message":"Event storage is temporarily unavailable"}}
```

La igualdad incluye todos los campos de contenido. Los textos, incluido el formato original del timestamp, se comparan exactamente. En `details`, PostgreSQL compara JSONB: el orden de las claves de objetos y las representaciones numéricas equivalentes no crean un conflicto; el orden de los arrays sí importa. Los números decimales se reciben sin conversión intermedia a `double`. Para filas SQL anteriores sin `original_timestamp`, se compara el instante que conserva `occurred_at`, limitado a microsegundos.

La clave primaria y `INSERT ... ON CONFLICT DO NOTHING` resuelven las peticiones simultáneas. La confirmación de reenvío utiliza una lectura posterior al intento de inserción para ver la transacción ganadora. No se actualiza la fila existente.

Sin el perfil, los endpoints de salud y alertas siguen arrancando; no se devuelve éxito aparente en ingesta. Con el perfil, PostgreSQL debe estar accesible al arrancar. El Compose del servicio SIEM no activa ni configura este perfil automáticamente: el arranque de ingesta se prueba localmente con Java y las variables de entorno del README. No se modifica el Dockerfile.
