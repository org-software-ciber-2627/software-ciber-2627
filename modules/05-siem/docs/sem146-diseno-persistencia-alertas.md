# SEM-146 · Diseño de la persistencia e identidad de las alertas

Historia [SEM-121 · HU23 - Conservar las alertas generadas](https://moncholi.atlassian.net/browse/SEM-121). Responsable JC; revisión técnica y aceptación del PO: Mario. Diseño redactado el 23/11/2026 sobre `main` en `efe6cc5`. Hito de la historia: 26/11, con almacenamiento, identidad de alerta y efectos públicos definidos.

Este documento fija el diseño que implementará SEM-147, probará SEM-148 y verificará SEM-149. No modifica código.

## Qué exige la historia

- Una alerta generada sigue en `GET /alerts` después de reiniciar el contenedor del SIEM.
- La alerta conservada mantiene el mismo `alert_id`: el SOAR registra solo alertas nuevas.
- Con PostgreSQL no disponible, `GET /alerts` responde 503, como indica el contrato.
- `GET /alerts` y `GET /alerts/{id}` no cambian su formato de respuesta.
- Precisiones del alcance: un reenvío conserva el identificador y evita duplicados tras reiniciar; el guardado debe ser consistente cuando el evento se conserva y falla una fase posterior; `severity: "info"` sigue sin generar alerta.

La historia y sus subtareas no piden una reconstrucción masiva de las alertas antiguas. El reenvío explícito de un evento ya guardado sin alerta sigue el contrato de ingesta.

## Situación de partida

| Pieza | Comportamiento actual |
| --- | --- |
| `EventService` | Guarda el evento en PostgreSQL con `saveIfAbsent` (`STORED`, `REPLAY` o `CONFLICT`) y después guarda la alerta en memoria, fuera de cualquier transacción. |
| `AlertRepository` | `LinkedHashMap` en memoria con un límite de 10 000 alertas (`siem.alerts.max-stored`, 507 `STORAGE_FULL`). Se pierde al reiniciar. |
| `AlertConverter` | `alert_id = "SIEM-ALERT-" + UUID.nameUUIDFromBytes(source + ":" + event_id)`, determinista. |
| `AlertNotificationListener` | Escribe una línea de log por cada alerta creada. No avisa a otro servicio. |
| Migraciones 001–004 | Solo la tabla `events`, con clave `(source, event_id)`. No existe tabla de alertas. |
| Configuración | `spring-jdbc` con `JdbcClient` y un `HikariDataSource` propio en el perfil `persistence`. No hay gestor de transacciones declarado. |

Riesgos actuales: un reinicio pierde todas las alertas; si falla la alerta después de guardar el evento, el evento queda sin alerta. El contrato ya prevé ese caso: «El reenvío idéntico puede crear la alerta cuando exista capacidad» (`contract/README.md`, `sem65-ingestion-proposal.md`, `sem29-deteccion-intentos-fallidos.md`).

## Decisiones

### D1. Tabla `alerts` en la migración 005

Se añade `db/init/005-create-alerts.sql`. No se modifican 001–004.

```sql
-- Persist generated alerts so they survive restarts.
BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    alert JSONB NOT NULL CHECK (jsonb_typeof(alert) = 'object'),
    CONSTRAINT alerts_identity_matches CHECK (
        (alert -> 'alert_id') IS NOT DISTINCT FROM to_jsonb(alert_id)
        AND (alert -> 'source') IS NOT DISTINCT FROM to_jsonb(source)
        AND (alert -> 'event_id') IS NOT DISTINCT FROM to_jsonb(event_id)
    ),
    CONSTRAINT alerts_event_unique UNIQUE (source, event_id),
    CONSTRAINT alerts_event_fk FOREIGN KEY (source, event_id) REFERENCES events (source, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts (created_at, alert_id);
COMMIT;
```

- `alert_id` es la clave primaria: no puede haber dos alertas con el mismo identificador.
- `UNIQUE (source, event_id)` garantiza una sola alerta por evento.
- La clave foránea impide una alerta sin su evento.
- La restricción de identidad exige que las tres claves estén presentes en el JSON como cadenas y coincidan con las columnas. Así el identificador devuelto por el listado también sirve para consultar el detalle.
- `alert` guarda las once claves del esquema `Alert` tal como se generaron. Si el conversor cambia en el futuro, las alertas ya entregadas al SOAR y al Dashboard no se alteran.
- JSONB no conserva el orden de las claves ni la representación textual de algunos números. Ocurre lo mismo con `details` en `events` y en `GET /events`. El contrato define campos, no un orden.

### D2. Identidad estable

Se mantiene exactamente el cálculo actual de `alert_id`. Como depende solo de `source` y `event_id`, el identificador es el mismo antes y después de un reinicio y en cualquier reenvío.

### D3. Evento y alerta en una sola transacción

`EventService` ejecuta la escritura dentro de una transacción con `TransactionTemplate` y un `DataSourceTransactionManager` en `EventPersistenceConfiguration`. El gestor y ambos repositorios comparten el mismo `DataSource`. Se configura `READ COMMITTED` explícitamente porque `saveIfAbsent` necesita que la lectura posterior al `INSERT … ON CONFLICT DO NOTHING` pueda ver la transacción ganadora.

En `alerts`, el `INSERT` usa `ON CONFLICT (source, event_id) DO NOTHING`. Si la alerta ya existe para ese evento, se conserva la original. Cualquier otro conflicto, incluido el mismo `alert_id` asociado a otro evento, es un error de integridad.

| Caso | Escrituras | Respuesta | Log de alerta |
| --- | --- | --- | --- |
| Evento nuevo, severidad distinta de `info`, con capacidad para la alerta | Evento y alerta | 200 | Sí |
| Evento nuevo `info` | Solo evento | 200 | No |
| Reenvío idéntico con alerta ya guardada | Ninguna | 200 | No |
| Reenvío idéntico de un evento que necesita una alerta, con capacidad | Alerta | 200 | Sí |
| Reenvío idéntico `info` | Ninguna | 200 | No |
| Misma identidad con otro contenido | Ninguna | 409 `EVENT_ID_CONFLICT` | No |
| Evento que necesita una alerta nueva y alcanza el umbral de D7, si se conserva el 507 | Se confirma el evento nuevo o se conserva el existente. No se inserta la alerta | 507 `STORAGE_FULL` | No |
| Almacenamiento no disponible antes de confirmar | Se revierten las escrituras de la petición. Si el evento ya existía, permanece | 503 `STORAGE_UNAVAILABLE` | No |
| Error de esquema, integridad o mapeo | Se revierten las escrituras de la petición | 500 | No |

Clasificar los fallos de conexión, adquisición, consulta y commit fuera del callback transaccional. Si se pierde la conexión durante el commit, su resultado puede ser incierto para el SIEM. El cliente recibe 503 y puede reenviar el mismo evento sin crear duplicados. Si se conserva el 507, el callback devuelve un resultado de capacidad que permite confirmar la transacción. El servicio traduce ese resultado a 507 después del commit.

El cuarto caso cubre los eventos guardados antes de aplicar 005 y aplica la regla ya publicada en el contrato. No es una reconstrucción del histórico: solo se crea la alerta del evento que el productor reenvía.

Si la alerta ya existe, se conserva tal como se guardó, aunque la versión vigente del conversor produjera otros campos.

### D4. Log después del commit

La transacción devuelve si la fila de alerta se ha insertado. `AlertService.emitAlert` se llama después del commit y solo en ese caso. El fallo del listener se registra sin incluir el contenido del evento y no cambia el acuse de una escritura ya confirmada. Una caída entre el commit y el log puede dejar la alerta guardada sin esa línea de log. La garantía de entrega de notificaciones queda fuera de esta historia.

### D5. Concurrencia

Dos peticiones idénticas simultáneas para un evento nuevo que debe generar alerta compiten en el `INSERT` de `events`. PostgreSQL bloquea la segunda hasta que la primera termine:

- Si la primera confirma el evento y su alerta, la segunda obtiene `REPLAY` y devuelve 200 al encontrar la alerta. Resultado: una fila de evento, una alerta y un solo log.
- Si la primera confirma solo el evento con 507, la segunda obtiene `REPLAY` y vuelve a comprobar si puede completar la alerta según D7.
- Si la primera se deshace, la segunda puede insertar el evento y evalúa la creación de la alerta según D7.

Para dos reenvíos de un evento histórico que ya existe sin alerta, ambas peticiones pueden llegar al `INSERT` de alertas si pasan el control de capacidad. La restricción única de `alerts` decide cuál la crea. Si una alcanza el umbral al contar, vuelve a comprobar si la otra ya confirmó la alerta antes de devolver 507. Esa segunda comprobación reduce la carrera, pero no la elimina: con `READ COMMITTED` no ve una alerta que la otra transacción todavía no ha confirmado. En ese caso responde 507 aunque la alerta acabe existiendo, y el siguiente reenvío recibe 200. El efecto es inocuo: no hay duplicados ni pérdida de la alerta.

No hace falta `synchronized` ni bloqueos en Java. A diferencia del `synchronized` actual, la garantía la da la base de datos, así que se mantiene aunque haya varias instancias del SIEM sobre la misma base.

### D6. Consultas

| Operación | Consulta | Error del almacén |
| --- | --- | --- |
| `GET /alerts` | `SELECT alert FROM alerts ORDER BY created_at, alert_id` | 503 `STORAGE_UNAVAILABLE` |
| `GET /alerts/{id}` | `SELECT alert FROM alerts WHERE alert_id = :id`; 404 `ALERT_NOT_FOUND` si no existe | 503 `STORAGE_UNAVAILABLE` |

- Los errores de conexión o timeout se traducen a `AlertStorageUnavailableException`, que ya tiene manejador. Los errores de esquema o mapeo responden 500. Se mantiene el límite de tiempo de las consultas con un valor explícito, como ya hace el histórico de eventos.
- El orden por fecha de creación da una salida estable, pero sigue sin ser contractual: el contrato SEM-68 no garantiza orden.
- Sin perfil `persistence` no hay almacén de alertas y los GET responden 503. Hoy responden con una lista vacía, y la guía `sem67-persistence-guide.md` lo documenta así. El cambio es coherente con el criterio de la historia y con el contrato: «Los fallos identificados del almacén producen 503».
- El listado es completo y su coste de lectura, memoria y transferencia crece con el volumen de alertas. Antes de retirar el límite actual, SEM-147 debe acordar con SOAR y Dashboard un presupuesto de tamaño de respuesta y concurrencia y SEM-148 debe verificarlo. Si hace falta cambiar el contrato, la alternativa debe acordarse con los consumidores.

### D7. Límite de capacidad y 507

Si se conserva el 507, aplicar `siem.alerts.max-stored` como límite blando, sin un bloqueo global de capacidad. Tras guardar o reconocer el evento, los eventos `info` devuelven 200 sin consultar `alerts`. Para el resto, el orden dentro de la transacción es:

1. Comprobar si ya existe la alerta (`SELECT 1 FROM alerts WHERE source = :source AND event_id = :eventId`). Si existe, devolver 200 sin contar filas.
2. Si no existe, ejecutar `SELECT count(*) FROM alerts`.
3. Si el recuento está por debajo del umbral, insertar con `INSERT … ON CONFLICT (source, event_id) DO NOTHING`.

Si el recuento alcanza el umbral, volver a comprobar si ya se confirmó la alerta de ese evento. Si sigue sin existir, confirmar el evento y responder 507 `STORAGE_FULL` después del commit. Un reenvío posterior puede completar la alerta cuando haya capacidad, como establece el contrato actual.

Varias transacciones pueden observar un recuento inferior al umbral e insertar a la vez. Con el mismo umbral en todas las instancias, una alerta como máximo por transacción y todas las escrituras sujetas a este control, el exceso queda acotado por el número de transacciones de ingesta simultáneas. El pool actual admite hasta 5 conexiones por instancia según `EventPersistenceConfiguration`, así que 5 por instancia es una cota conservadora, no un máximo global de 5. El recuento exacto añade una consulta por alerta nueva. Medir su coste cerca del umbral por defecto de 10 000 alertas en SEM-148.

**Riesgo de saturación.** El SIEM actual no autentica la ingesta y el módulo limita el tamaño de cada petición, pero no su frecuencia. Un cliente no autorizado que pueda alcanzar la API puede agotar la capacidad con eventos falsos. Los eventos legítimos que necesiten una alerta nueva podrían seguir recibiendo 507 después de reiniciar, porque las alertas seguirían ocupando espacio en PostgreSQL. El límite blando reduce la contención, pero mantiene ese riesgo. El 507 confirma los eventos aunque no se cree la alerta, por lo que `events` puede seguir creciendo.

**Saturación sin ataque.** Con el almacén en memoria, `max-stored` protege la memoria y se vacía en cada reinicio. En PostgreSQL pasa a ser un cupo para toda la vida del sistema. Sin una política de retención, el tráfico legítimo acaba alcanzando el umbral y, desde ese momento, toda alerta nueva recibe 507 de forma permanente. Mantener el límite cambia su significado: deja de ser una protección temporal y pasa a ser un tope de alertas acumuladas.

Opciones para Mario:

1. Mantener el límite blando y el 507, y aceptar explícitamente el riesgo residual hasta SEM-133. Documentar un procedimiento de limpieza manual autorizada para recuperar capacidad. Sin una política de retención aprobada, no se borran alertas automáticamente. Esta opción exige además una de estas medidas: un umbral dimensionado para el volumen esperado, con un aviso en el log al acercarse a él, o una política de retención aprobada. Sin ninguna de las dos, el SIEM deja de generar alertas al alcanzar el umbral.
2. Retirar el 507 una vez acordado con SOAR y Dashboard cómo acotar el tamaño y el coste del listado. Actualizar entonces el contrato de ingesta.

### D8. Arranque y volúmenes existentes

- Con un volumen nuevo, `docker-entrypoint-initdb.d` aplica 001–005 automáticamente, tanto en `docker-compose.yml` como en `compose.storage.yml`.
- Con un volumen existente, los scripts de inicialización no se ejecutan. Hay que aplicar las migraciones pendientes en orden con la aplicación detenida. Este ejemplo es para el Compose local del módulo desde la raíz del repositorio. Para el Compose común, se usa el proyecto, archivo y base del despliegue común, conservando su volumen. Se documentará en `sem67-persistence-guide.md`:

```bash
docker compose --env-file /dev/null -f modules/05-siem/compose.storage.yml exec -T siem-db psql -X -U siem -d siem_bd -v ON_ERROR_STOP=1 < modules/05-siem/db/init/005-create-alerts.sql
```

- Aplicar 005 en una transacción. El `lock_timeout` acota la espera por el bloqueo de `events`. `IF NOT EXISTS` permite repetir la misma migración, pero no corrige una tabla preexistente con otro esquema.
- Propuesta: al arrancar con el perfil `persistence`, comprobar que la migración se aplicó y fallar con un mensaje claro si falta. Sin esa comprobación, la primera consulta o escritura que acceda a la tabla fallará por un error de esquema.

### D9. Límite de exposición del despliegue

El SIEM de partida acepta ingesta y consultas sin autenticar al cliente. El Compose común publica su puerto y Dashboard también reenvía consultas al SIEM. Las alertas persistentes amplían el periodo durante el que se pueden consultar datos. Verificar SEM-133 y los controles de acceso del contrato con G1 antes de exponer esos endpoints a redes o usuarios no confiables. En la base de datos, separar el rol de migraciones del rol de aplicación y limitar el segundo a las operaciones que necesita. Hoy la aplicación se conecta como `siem` (`siem.database.username`), que es el `POSTGRES_USER` de `docker-compose.yml` y `compose.storage.yml`; la imagen oficial de PostgreSQL crea ese usuario como superusuario. Las consultas van parametrizadas, pero el rol incumple el mínimo privilegio. Su corrección corresponde a la revisión de seguridad (SEM-159/SEM-161), no a SEM-147.

La saturación descrita en D7 puede impedir que se creen alertas nuevas incluso después de reiniciar. Mantener ese riesgo visible hasta verificar los controles de ingesta de SEM-133.

## Alternativas descartadas

| Alternativa | Motivo |
| --- | --- |
| Reconstruir las alertas desde `events` al arrancar o en cada consulta | Depende de la versión vigente del conversor y puede cambiar alertas ya entregadas. Además crearía alertas de eventos antiguos que la historia no pide. |
| Una columna por campo de la alerta | Más SQL y más migraciones si cambia el esquema `Alert`. La alerta se guarda y se devuelve entera; el filtrado se hace en el cliente. |
| Dos escrituras separadas con compensación | Puede dejar un evento sin alerta si el proceso cae entre ambas. La transacción lo evita sin código adicional. |
| Outbox de notificaciones | La notificación actual es solo un log. Queda fuera del alcance de la HU23. |

## Cambios previstos para SEM-147

- `db/init/005-create-alerts.sql`.
- `AlertRepository`: implementación PostgreSQL con `insertIfAbsent`, `findAll` y `findById` en el perfil `persistence`, y una implementación sin almacén que lanza `AlertStorageUnavailableException`.
- `EventService`: transacción única y log después del commit; desaparece el parámetro `confirmedReplay`.
- `EventPersistenceConfiguration`: `DataSourceTransactionManager` y `TransactionTemplate`.
- `AlertController` y `AlertQueryService`: sin cambios de formato; propagan el 503.
- `scripts/test-storage.py`: añadir 005 al esquema nuevo y a la prueba de migración de un volumen antiguo.
- Documentación: guía de persistencia, README y contrato (507), si Mario aprueba D7.

## Pruebas para SEM-148

| Caso | Resultado esperado |
| --- | --- |
| Evento nuevo | Una fila en `events`, una en `alerts`, mismo `alert_id` que hoy |
| Reenvío idéntico | 200, sin filas nuevas ni segundo log |
| Reenvío tras reiniciar el contexto o el contenedor | 200, misma alerta, sin duplicado |
| Reenvío de un evento guardado sin alerta | Se crea su alerta una sola vez |
| Dos peticiones idénticas concurrentes | Una fila en cada tabla y un log |
| Peticiones concurrentes alrededor del límite, si se conserva el 507 | El exceso no supera el número de transacciones de ingesta simultáneas. Todos los eventos quedan confirmados. Los que crean alerta reciben 200 y los que quedan sin alerta por capacidad reciben 507 |
| Almacén lleno y reenvío idéntico de un evento cuya alerta ya existe | 200 sin contar filas, sin alerta duplicada ni segundo log |
| Misma identidad con otro contenido | 409, evento y alerta originales intactos |
| Indisponibilidad al insertar la alerta de un evento nuevo | 503 y el evento tampoco queda guardado |
| Indisponibilidad al completar un reenvío de un evento histórico | 503, el evento original se conserva. Un reenvío posterior puede completar la alerta |
| Fallo de esquema o integridad durante la escritura | 500 y se revierten las escrituras de la petición |
| Fallo del listener después del commit | Evento y alerta confirmados, sin segundo log al reenviar |
| Evento `info` | Evento guardado, sin alerta |
| PostgreSQL caído en `GET /alerts` y `GET /alerts/{id}` | 503 `STORAGE_UNAVAILABLE`, nunca 200 con lista vacía |
| Alerta inexistente | 404 `ALERT_NOT_FOUND` |
| Formato | Mismas once claves y contenedor `{"alerts": [...]}` que antes |
| Migración | 005 se aplica sobre un volumen con datos de 001–004, se puede reaplicar y conserva los eventos. Verificar rechazados los JSON con identidad ausente, nula o distinta |

## Verificación para SEM-149

Con el Compose común y el volumen persistente: generar una alerta, reiniciar el contenedor `siem`, comprobar que `GET /alerts` devuelve el mismo `alert_id`, reenviar el evento sin que aparezca un duplicado, y detener PostgreSQL para comprobar el 503. `efe6cc5` ya incluye PostgreSQL en el Compose común. Queda verificar la integración de SEM-118 y el consumo real desde SOAR y Dashboard.

## Pendiente de revisión

1. D7: mantener el límite blando o retirar el 507 tras acordar el coste del listado con SOAR y Dashboard. Si se mantiene, confirmar la aceptación del riesgo de saturación hasta SEM-133, el procedimiento de limpieza manual y cómo se evita que el tráfico legítimo agote el cupo: un umbral dimensionado con aviso, o una política de retención.
2. D6: 503 en los GET cuando se arranca sin perfil `persistence`.
3. D8: comprobación de la tabla `alerts` al arrancar.
