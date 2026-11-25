# HU16: evidencias para revisión y aceptación

Evidencias de la versión de HU16 del 03/11/2026. La versión integrada incorpora también la persistencia de eventos de HU8.

## Alcance de la entrega

La versión original incluía la generación de HU13, el detalle de HU17 y las subtareas SEM-68 a SEM-72. Los resultados siguientes corresponden a esa versión.

## Evidencias

- Maven clean verify tras integrar main: 23 pruebas, 0 fallos, 0 errores, 0 omitidas.
- Ejecución anterior de CI de SEM-71 sobre 31e573b: https://github.com/org-software-ciber-2627/software-ciber-2627/actions/runs/41655794048 ; 22 pruebas correctas. No demuestra el resultado de CI de esta nueva revisión.
- Instancia local nueva del JAR, ligada a loopback: respuesta inicial de GET /alerts exactamente {"alerts":[]}.
- [Smoke HTTP](hu16-smoke-result.json): 28 comprobaciones correctas con cuatro ejemplos de tres productores, incluido Honeypot actual. Los eventos se envían por POST y se recuperan por listado y detalle. El puerto aleatorio del informe ya no está activo.
- Fallos de almacén y errores inesperados: tests MVC de listado y detalle, 503/500, cuerpo exacto y mensajes genéricos. Es inyección de fallos, no una caída de base de datos.
- Test HTTP de 150 alertas: sin truncado; once campos, null conservado, comparación sin orden impuesto.

## Guía de revisión

1. Ejecutar las instrucciones del README en una instancia de desarrollo.
2. Comprobar que el listado vacío es 200 y que después de POST aparece la alerta real.
3. Consultar su alert_id en el detalle y comparar campos.
4. Revisar los tests de errores y el advice compartido.
5. Ejecutar la regresión conjunta de almacenamiento, histórico y alertas con el [procedimiento SEM-66](sem66-storage-tests.md).

El almacén de alertas está en memoria. Los eventos de PostgreSQL se conservan al reiniciar el SIEM.
