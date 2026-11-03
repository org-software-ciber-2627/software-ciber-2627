# SEM-68: contrato de consulta de alertas

Acuerdo del 03/11/2026 confirmado por Claudio, PO, en el mensaje aportado por JC. Define el comportamiento objetivo de HU16 y HU17; no acredita que el manejo de errores esté implementado.

## Listado

GET /alerts devuelve 200 con {"alerts": [...]} y los once campos del esquema Alert existente. Si la consulta funciona y no hay alertas, devuelve {"alerts": []}. Se consulta el almacén completo, sin truncado, filtros, paginación ni orden garantizado. Dashboard ordena y filtra en cliente; SOAR acepta este contenedor.

## Errores comunes al listado y al detalle

| Estado | Código | Mensaje |
| --- | --- | --- |
| 503 | STORAGE_UNAVAILABLE | Alert storage is temporarily unavailable |
| 500 | INTERNAL_ERROR | An unexpected error occurred |

Ambas rutas usan el contenedor {"error":{"code":"...","message":"..."}}. Un fallo nunca se representa con una lista vacía. El 500 no incluye excepciones, trazas ni detalles internos. El detalle conserva el 404 ALERT_NOT_FOUND cuando la consulta funciona pero el ID no existe.

La implementación posterior debe centralizar estos errores en un @RestControllerAdvice común: fallos identificados del almacén producen 503; errores inesperados producen 500. No confundir todas las RuntimeException con indisponibilidad. La ausencia de una dependencia obligatoria puede impedir el arranque, por lo que este contrato HTTP no garantiza que la aplicación arranque sin repositorio.

## Acceso al almacén

HU16 usa services.AlertRepository.findAll() de SEM-30, commit 4d4b198. El detalle de SEM-33 usa findById() de ese mismo tipo desde a4d8d46. La combinación se verificó localmente con 14 pruebas sin fallos; la rama de Claudio necesita integrar la dependencia de Mario para compilar por sí sola.

El repositorio actual es en memoria y se pierde al reiniciar. No se añade otro almacén ni se implementa persistencia en esta subtarea.

## Evidencia y siguiente paso

- Formato y ausencia de orden garantizado: contrato de Dashboard en modules/07-dashboard/contract/README.md.
- Contenedor consumido por SOAR: modules/06-soar/contract/README.md.
- Respuestas 200, 404, 503 y 500: openapi.json, según la ruta.
- Claudio acepta las respuestas 503/500 comunes y el mensaje genérico del 500, solicita añadirlas al OpenAPI y da SEM-68 por buena con ese cambio.
- Comunicación a G6 y G7 prevista en el Scrum de Scrums; no se registra como realizada.
- Implementación del advice, pruebas HTTP y CI pendientes en el desarrollo posterior. La aceptación de SEM-68 no cierra HU16 ni HU17.
