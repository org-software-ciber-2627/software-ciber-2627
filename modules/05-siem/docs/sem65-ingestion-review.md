# SEM-65: recepción conectada al almacenamiento

Fecha: 22/10/2026. Rama local: `equipo-05-siem`. Cambios sin publicar, pendientes de revisión de JC.

## Resultado

`POST /events` conserva la validación existente y utiliza el repositorio PostgreSQL con el perfil `persistence`. Devuelve 200 después de confirmar una inserción o un reenvío idéntico de `(source, event_id)`. Si cambia el contenido devuelve 409 y conserva el original. Un fallo de almacenamiento devuelve 503 sin incluir SQL, datos del evento ni información de conexión en el error.

Sin el perfil, salud y alertas siguen disponibles pero una ingesta válida devuelve 503. El perfil persistente requiere PostgreSQL disponible al arrancar. Las alertas permanecen estáticas: no hay correlación ni generación de alertas en este cambio.

La inserción utiliza `ON CONFLICT DO NOTHING` y compara después el contenido existente. JSONB permite comparar objetos sin depender del orden de sus claves ni de tipos numéricos Java distintos. Se conserva la precisión decimal desde la lectura HTTP y el texto original del timestamp. La semántica detallada está en `contract/sem65-ingestion-proposal.md`.

Se añaden errores de almacenamiento en un advice separado. No se modifica `ApiErrorHandler`, `JsonContractConfiguration` ni el modelo `Event`, para limitar el conflicto con la validación de Darío.

## Acuerdos y alcance

JC aceptó la política 200/409 como propuesta, condicionada a comprobar los acuerdos existentes. Se revisaron GitHub en modo lectura y las secciones de contrato y acuerdos del Miro abierto en Brave. No se encontró una decisión vigente de Sprint 2 sobre reenvíos ni una actualización publicada de SEM-24. Esto no descarta cambios locales de Darío.

La política sigue pendiente de ratificación del equipo y coordinación con HU9. El OpenAPI y el README de `contract/` conservan el candidato del Sprint 1; Oliver debe revisar su actualización antes de integrar. La propuesta nueva se documenta por separado y no se presenta como acuerdo intergrupo.

## Evidencias locales

- Prueba inicial: dos fallos esperados, porque la ingesta todavía respondía 200 sin base de datos en lugar de 503.
- Una prueba adicional detectó que un decimal recibido por HTTP se reducía de `1234567890.12345678901234567890` a `1234567890.1234567`. Se corrigió la conversión del perfil persistente y la prueba pasó, incluido el conflicto entre valores que solo difieren en las últimas cifras.
- Suite completa con PostgreSQL real: **27 tests, 0 fallos, 0 errores, 0 omitidos**. Incluye diez pruebas del repositorio, nueve HTTP persistentes, seis del perfil predeterminado, una del arranque y una de error de almacenamiento.
- Concurrencia: doce reenvíos idénticos producen doce respuestas 200 y una fila; ocho contenidos distintos con la misma clave producen un 200, siete 409 y una fila.
- Migración aditiva aplicada dos veces sobre una base con esquema anterior: conserva la fila previa.
- Construcción del JAR: `./mvnw -o package`, correcta.
- JAR arrancado con el perfil persistente: una ingesta devuelve 200 y su fila está presente. Al detener la base aislada, la petición devuelve 503. Al restaurarla, el mismo evento devuelve 200 con una sola fila; cambiar el contenido devuelve 409.
- Sobre ese JAR pasaron las **15 comprobaciones HTTP** de `smoke-test.py`.
- Revisión estática independiente del código nuevo y modificado: sin incidencias bloqueantes. El revisor consultó los resultados de las 27 pruebas; no las ejecutó por su cuenta.
- Los contenedores, red y volumen de pruebas se eliminaron al terminar. No se utilizó ni migró el volumen existente de JC.
- Entorno: JDK 25.0.2, compilación configurada con release 21. No se ha acreditado ejecución con un runtime Java 21 ni CI.

Las pruebas usan credenciales aleatorias y `--env-file /dev/null`. Evidencias operativas locales fuera del repositorio: `../sem65-review-evidence/java-tests.log`, `application.log` y `smoke-test.json`.

## Revisión pendiente

1. JC revisa los cambios locales y el SQL aditivo antes de aplicarlo a su base.
2. El equipo y el responsable del contrato ratifican los códigos nuevos y el acuse; coordinación con HU9.
3. Revisión por otro miembro, CI de SEM-66 y aceptación del PO según la Definition of Done.
4. Configurar el perfil persistente para el despliegue compartido con su responsable. El servicio SIEM del Compose no lo activa automáticamente; el arranque probado aquí es el JAR local.

No se ha modificado ningún Dockerfile, no se ha leído ni versionado `.env`, y no se ha hecho commit, push ni PR durante SEM-65.

## Verificación posterior en la base local de JC (22/10/2026)

JC autorizó continuar de forma autónoma con los cambios y pruebas locales, reservando las publicaciones para su revisión. Se arrancó el contenedor existente `siem-sem63-siem-db-1`, conservando `siem-sem63_siem-postgres-data`.

Antes de migrar se creó un respaldo privado en formato PostgreSQL custom y se comprobó que `pg_restore --list` podía leerlo. Se conserva fuera del repositorio, en `../sem65-review-evidence/backups/`. Se aplicó el SQL aditivo dentro de una transacción y se comprobó que la fila previa mantenía el mismo contenido en sus ocho columnas originales.

La aplicación local quedó arrancada en `http://127.0.0.1:8005` con `persistence`. Se utilizó en memoria la credencial ya configurada en el contenedor, sin leer `.env`, modificarla ni mostrarla.

Prueba local: evento `SEM65-LOCAL-584e68d69303`, primera inserción 200, reenvío idéntico 200 y reenvío con título distinto 409. Se verificó una sola fila para esa clave, el título original y la fecha completa con nanosegundos. El evento de prueba se conserva identificado como tal; la fila previa no cambió.

La migración y el arranque locales ya están verificados. Siguen pendientes la ratificación del contrato, revisión humana, configuración del despliegue compartido, CI y aceptación del PO. No hay cambios publicados en GitHub.
