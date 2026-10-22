# SEM-64: persistencia de eventos desde Java

Fecha: 20 de octubre de 2026. Rama local: `equipo-05-siem`.

## Resultado y alcance

Implementación local preparada para la revisión de JC. `EventRepository` proporciona `save(Event)` y `findById(source, eventId)`. Reutiliza el modelo `Event` y no modifica controladores, el servicio de ingesta ni la API pública del histórico.

`PostgresEventRepository` utiliza consultas parametrizadas mediante Spring JDBC. Guarda todos los campos, mantiene `details` como objeto JSONB y recupera los números decimales sin convertirlos a coma flotante binaria. Un duplicado del mismo productor produce `DuplicateKeyException` y no sobrescribe el registro existente. Un par desconocido devuelve `Optional.empty()`.

`EventPersistenceConfiguration` crea el pool y `JdbcClient` únicamente con el perfil `persistence`. La configuración por defecto sigue arrancando sin base de datos. La aplicación Java requiere las variables de entorno correspondientes; no carga el `.env` de Compose automáticamente.

## Propuesta de migración pendiente de revisión

`002-add-original-timestamp.sql` añade la columna nullable `original_timestamp`, necesaria para conservar el texto completo de fechas con nanosegundos y su formato original. `occurred_at` conserva el instante a la precisión disponible en PostgreSQL. Los registros anteriores sin el texto original se recuperan a partir de `occurred_at` en UTC.

La migración se ha probado únicamente en una base de datos aislada. No se ha aplicado al volumen local de JC. El README explica cómo revisarla y aplicarla sin recrear el volumen.

## Verificación realizada

- Los siete tests Java originales pasaron antes de la implementación.
- El primer intento de ejecutar los tests nuevos falló al compilar porque el repositorio aún no existía.
- Tras implementar, se ejecutó la suite completa con PostgreSQL real: **17 tests, 0 fallos, 0 errores y 0 omitidos**.
- Los diez tests nuevos cubren los tres ejemplos del contrato, JSON anidado con nulos/Unicode/decimales precisos, conservación del timestamp original, duplicados sin sobrescritura, identificadores coincidentes en productores distintos, búsquedas inexistentes, comillas como datos, errores de fecha/restricciones y lectura de registros anteriores.
- En una base con el esquema previo y una fila existente, el segundo SQL se ejecutó dos veces y conservó la fila.
- Las pruebas utilizaron un proyecto y volumen PostgreSQL independientes. Sus recursos se eliminaron al finalizar.
- Entorno Java local: JDK 25.0.2, compilación configurada con release 21.
- Revisión estática independiente local: sin incidencias bloqueantes. El revisor no ejecutó los tests; los resultados anteriores proceden de la ejecución local documentada.

Sin `SIEM_TEST_DB_URL`, los tests PostgreSQL se omiten explícitamente. Esa ejecución no acredita la persistencia. Incorporarlos al pipeline corresponde a SEM-66.

## Pendiente

- Revisión de JC antes de cualquier publicación o aplicación de la migración a su volumen.
- Revisión por otro miembro del equipo, CI y aceptación del PO según la Definition of Done.
- Conectar `POST /events` y decidir la respuesta HTTP ante reenvíos en SEM-65.
- Acordar con Oliver la ampliación del acceso a datos para el histórico de HU10.

No se ha accedido a GitHub durante este trabajo. No se ha modificado ningún Dockerfile ni se ha leído o versionado `.env`. Las correcciones y archivos de SEM-64 permanecen locales y sin publicar.
