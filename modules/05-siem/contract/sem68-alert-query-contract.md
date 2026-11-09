# SEM-68: contrato de consulta de alertas

Contrato de consulta de HU16 y HU17, acordado el 03/11/2026.

## Listado

GET /alerts devuelve 200 con {"alerts": [...]} y los once campos del esquema Alert existente. Si la consulta funciona y no hay alertas, devuelve {"alerts": []}. Se consulta el almacén completo, sin truncado, filtros, paginación ni orden garantizado. Dashboard ordena y filtra en cliente; SOAR acepta este contenedor.

## Errores comunes al listado y al detalle

| Estado | Código | Mensaje |
| --- | --- | --- |
| 503 | STORAGE_UNAVAILABLE | Alert storage is temporarily unavailable |
| 500 | INTERNAL_ERROR | An unexpected error occurred |

Ambas rutas usan el contenedor {"error":{"code":"...","message":"..."}}. Un fallo nunca se representa con una lista vacía. El 500 no incluye excepciones, trazas ni detalles internos. El detalle conserva el 404 ALERT_NOT_FOUND cuando la consulta funciona pero el ID no existe.

Un `@RestControllerAdvice` común centraliza estos errores. Los fallos identificados del almacén producen 503; errores inesperados producen 500. No confundir todas las RuntimeException con indisponibilidad. La ausencia de una dependencia obligatoria puede impedir el arranque, por lo que este contrato HTTP no garantiza que la aplicación arranque sin repositorio.

## Acceso al almacén

Listado y detalle consultan el mismo repositorio de alertas. Usan `findAll()` y `findById()`, respectivamente.

El repositorio actual es en memoria y se pierde al reiniciar. No se añade otro almacén ni se implementa persistencia en esta subtarea.

## Evidencia y siguiente paso

- Formato y ausencia de orden garantizado: contrato de Dashboard en modules/07-dashboard/contract/README.md.
- Contenedor consumido por SOAR: modules/06-soar/contract/README.md.
- Respuestas 200, 404, 503 y 500: openapi.json, según la ruta.
