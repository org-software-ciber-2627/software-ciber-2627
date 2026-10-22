# Equipo 5 · SIEM · Sprint 2 (revisión local)

Base del Sprint 1 ampliada localmente en SEM-63, SEM-64 y SEM-65. Requiere revisión de JC, revisión cruzada y aceptación del PO antes de publicar. Las respuestas nuevas de ingesta son una propuesta pendiente de ratificación del equipo.

## Alcance

Servidor Java 21 y Spring Boot 4.1.1. Con el perfil `persistence`, recibe un evento JSON por petición, valida la cabecera común y confirma su almacenamiento en PostgreSQL antes de devolver el acuse. Publica tres alertas estáticas, una por productor, conservando sus campos y valores nulos.

Los reenvíos idénticos de `(source, event_id)` no crean otra fila; un contenido distinto con la misma clave produce 409. Sin el perfil `persistence`, la ingesta devuelve 503. No hay correlación ni autenticación real. Enviar eventos no cambia la lista de alertas. La integración externa sigue pendiente.

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

## API local propuesta

| Ruta | Resultado |
| --- | --- |
| `GET /health` | 200, `{"status":"ok","module":"05-siem"}` |
| `POST /events` | 200 tras guardar o confirmar un reenvío idéntico; 400 para un evento inválido; 409 si cambia el contenido de la misma clave; 415 para un Content-Type distinto de JSON; 503 sin almacenamiento disponible |
| `GET /alerts` | 200, `{"alerts":[...]}` con tres ejemplos |
| `GET /alerts/{id}` | 200 con una alerta; 404 con error JSON si no existe |

Se conserva el 200/400 comunicado a G3 y se proponen 409/503 para SEM-65. Consulta `contract/sem65-ingestion-proposal.md`. El OpenAPI y el README dentro de `contract/` conservan el candidato del Sprint 1; su actualización debe revisarse con el responsable del contrato antes de integrar. No representan todavía esta propuesta de ingesta persistente.

```bash
curl -i -H 'Content-Type: application/json' --data-binary @modules/05-siem/contract/examples/grupo_3_honeypot.json http://localhost:8005/events
curl -i http://localhost:8005/alerts
curl -i http://localhost:8005/alerts/SIEM-ALERT-EJEMPLO-003
```

## Contrato y comprobaciones

- `contract/openapi.json`: candidato histórico del mock Sprint 1.
- `contract/sem65-ingestion-proposal.md`: cambios locales de ingesta para revisar en Sprint 2.
- `contract/event-schema.json`: esquema local del SIEM. No sustituye el esquema global pendiente de acuerdo.
- `contract/examples/`: ejemplos G2, G3 y G4.
- `mocks/alerts.json`: fuente única de las tres alertas, incluida en el JAR.

Desde `modules/05-siem`:

```bash
./mvnw clean verify
```

Las pruebas arrancan el servidor en un puerto aleatorio y comprueban los tres productores, los campos obligatorios, valores inválidos, JSON incorrecto, los tres detalles y el error 404. No certifican servicios de otros equipos.

Consultar `docs/estado-integracion.md` para evidencias y acuerdos pendientes. La API no expone credenciales en los logs; los datos de `credential` de los ejemplos son datos ficticios de laboratorio.

Comprobación HTTP con el perfil `persistence` activo y ambos scripts SQL aplicados, desde la raíz del repositorio. Inserta los ejemplos de laboratorio y puede repetirse si esos identificadores conservan el mismo contenido:

```bash
python3 modules/05-siem/scripts/smoke-test.py http://localhost:8005
```

Validación del contrato local. Requiere `jsonschema>=4,<5` en un entorno Python:

```bash
python3 modules/05-siem/scripts/verify-contract.py
```

## Base de datos de eventos (SEM-63)

El Sprint 2 incorpora PostgreSQL y la conexión local de `POST /events` mediante SEM-64/SEM-65. Activa el perfil Spring `persistence` y aplica los dos scripts SQL antes de probar la ingesta.

Desde la raíz del repositorio, copia `.env.example` a `.env` y define `SIEM_DB_PASSWORD` con una contraseña local. El archivo `.env` está excluido de Git. Después arranca la base de datos:

```bash
docker compose --profile siem-db up -d siem-db
docker compose ps siem-db
```

El perfil `siem-db` es optativo. El compose general se puede utilizar sin configurar esta contraseña; PostgreSQL exige una contraseña no vacía cuando se inicializa su servicio. No se habilita autenticación de confianza para conexiones remotas.

El servicio se conecta a la red Docker `ciberurjc` y escucha en `siem-db:5432` dentro de ella. Desde el ordenador se publica solo en `127.0.0.1:5433`, configurable con `SIEM_DB_PORT`. La base de datos y el usuario son `siem`.

El esquema inicial crea la tabla `events` a partir de `modules/05-siem/db/init/001-create-events.sql`. La clave primaria es `(source, event_id)`, porque el contrato define el identificador como único dentro de cada productor. El mismo identificador puede existir en productores distintos. `occurred_at` almacena el instante del campo `timestamp` del contrato y `details` se almacena como JSONB, limitado a objetos JSON. Las restricciones también validan `source`, `severity` y que los textos obligatorios contengan al menos un carácter no blanco. El volumen nombrado `siem-postgres-data` conserva los datos al recrear el contenedor.

El script de inicialización se ejecuta automáticamente solo con un volumen de datos vacío. Modificar el SQL no migra una base de datos ya inicializada. Si se utilizó una versión anterior del esquema, hay que preparar su migración conservando los datos antes de continuar.

Para comprobar el esquema y el estado del servicio:

```bash
docker compose exec siem-db psql -U siem -d siem -c '\d events'
docker compose exec siem-db pg_isready -U siem -d siem
```

Para detener el contenedor sin borrar los datos:

```bash
docker compose stop siem-db
```

Para recrear solo el contenedor conservando los datos:

```bash
docker compose stop siem-db
docker compose rm -f siem-db
docker compose --profile siem-db up -d --wait siem-db
```

No uses `down -v` para conservar los datos, porque elimina los volúmenes del proyecto. SEM-65 conecta la inserción HTTP y el control de reenvíos con esta base de datos.

## Acceso a eventos desde Java (SEM-64)

`EventRepository` ofrece `save(Event)` y `findById(source, eventId)`. La implementación PostgreSQL reutiliza el modelo `Event`, convierte el instante a `occurred_at` y conserva `details` como JSONB. Los valores se envían mediante parámetros SQL. Un identificador desconocido devuelve `Optional.empty()`; insertar un par `(source, event_id)` repetido produce `DuplicateKeyException` y no sobrescribe la fila anterior. SEM-65 utiliza `saveIfAbsent(Event)` para distinguir inserciones, reenvíos idénticos y conflictos sin sobrescribir datos.

El acceso a datos se habilita solo con el perfil Spring `persistence`. El perfil crea un pool de hasta cinco conexiones y requiere `SIEM_DB_PASSWORD` como variable de entorno. La aplicación Java no carga automáticamente el archivo `.env` de Docker Compose.

Variables de configuración:

| Variable | Uso |
| --- | --- |
| `SIEM_DB_PASSWORD` | Contraseña del usuario `siem`, obligatoria al activar el perfil. |
| `SIEM_DB_PORT` | Puerto local, por defecto `5433`. |
| `SIEM_DB_URL` | URL JDBC opcional. Por defecto `jdbc:postgresql://127.0.0.1:<SIEM_DB_PORT>/siem`; dentro de la red Docker debe apuntar a `jdbc:postgresql://siem-db:5432/siem`. |

Con PostgreSQL arrancado y las variables configuradas en el entorno, desde `modules/05-siem`:

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=persistence
```

### Actualización del esquema existente

PostgreSQL almacena `TIMESTAMPTZ` con precisión de microsegundos. Para recuperar el texto completo del evento, incluidas fechas con nanosegundos o ceros finales, SEM-64 añade `original_timestamp`. Los registros anteriores pueden tener esa columna nula y se recuperan utilizando `occurred_at` en UTC.

Con un volumen nuevo, los scripts de `db/init` se aplican automáticamente en orden. Si el volumen ya existía, revisa y aplica el segundo script antes de utilizar el repositorio. Desde la raíz del repositorio:

```bash
docker compose exec -T siem-db psql -U siem -d siem -v ON_ERROR_STOP=1 < modules/05-siem/db/init/002-add-original-timestamp.sql
```

Este script añade una columna nullable, se puede repetir y conserva las filas existentes. No cambia la clave primaria ni borra datos. No reconstruye la precisión que ya se hubiera perdido al guardar fechas anteriores.

### Pruebas del repositorio

`PostgresEventRepositoryTests` necesita una base PostgreSQL de pruebas con ambos scripts SQL aplicados. Configura `SIEM_TEST_DB_URL`, `SIEM_TEST_DB_USER` y `SIEM_TEST_DB_PASSWORD` en el entorno de pruebas y ejecuta `./mvnw test`. Los tests generan identificadores propios y limpian únicamente sus filas.

Si falta `SIEM_TEST_DB_URL`, los tests PostgreSQL se omiten explícitamente; el resultado no acredita la persistencia. Los tests de arranque, validación, alertas y error de almacenamiento siguen ejecutándose con el perfil por defecto. En él se comprueba que una ingesta válida responde 503.

`PersistentEventHttpTests` comprueba la conexión HTTP de SEM-65 con PostgreSQL real, incluidos reenvíos simultáneos, conflictos, decimales precisos, fechas con nanosegundos y registros anteriores. Usa las mismas variables `SIEM_TEST_DB_*` y una base de pruebas. La API del histórico de Oliver y las reglas de validación de Darío quedan fuera de esta implementación. Consulta `docs/sem65-ingestion-review.md` para las evidencias y limitaciones.
