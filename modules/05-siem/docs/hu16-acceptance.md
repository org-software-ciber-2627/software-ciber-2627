# HU16: evidencias para revisión y aceptación

Preparado el 03/11/2026. El código del listado está implementado; aceptación de Claudio como PO y revisión por compañero pendientes.

## Alcance de la entrega

Incluye HU13 de Mario como dependencia, adaptación de detalle de Claudio, SEM-68 a SEM-71 y documentación de SEM-72. Main se ha integrado conservando su prueba de Honeypot actual. No incluye la rama de persistencia de eventos HU8, que sigue necesitando integración propia.

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
5. Revisar la PR, CI del SHA final y los límites de esta entrega.
6. Claudio registra aceptación o cambios requeridos para HU16. Hasta entonces, no cerrar SEM-72 ni la historia.

## Pendientes explícitos

- Revisión de código por otro miembro mediante PR.
- Aceptación de HU16 por Claudio como PO.
- Integración en main tras revisión y comprobaciones.
- Comunicación del contrato de errores a G6/G7 en Scrum de Scrums, todavía no acreditada.
- Persistencia de eventos HU8 e integración conjunta, y futura persistencia de alertas. El almacenamiento actual se pierde al reiniciar.

El acuerdo de Claudio para SEM-68 acepta el contrato; no equivale a aceptar el código de HU16. No se han enviado mensajes a compañeros ni solicitado revisores automáticamente.
