# Requisitos del SIEM para el Compose común

## Alcance y estado

Guía técnica de SEM-128, parte de SEM-118. Describe la configuración que necesita el módulo 5 para recibir y consultar eventos con PostgreSQL en el despliegue común.

La configuración compartida corresponde a G7. G5 proporciona los requisitos del SIEM, los scripts SQL y las comprobaciones de aceptación; ambos equipos contrastan después el despliegue real.

A fecha del 28/11/2026, la [PR #96](https://github.com/org-software-ciber-2627/software-ciber-2627/pull/96) ya incorporó PostgreSQL y el perfil `persistence` al Compose común. La [PR #134](https://github.com/org-software-ciber-2627/software-ciber-2627/pull/134) añadió las variables de cuentas de servicio a Identidad. El mapeo del publicador IDS a `svc-ids` está en la [PR #132](https://github.com/org-software-ciber-2627/software-ciber-2627/pull/132), pendiente de integrar. Las pruebas locales y sus límites están en [SEM-131](sem131-compose-verification.md).

La [guía de persistencia](sem67-persistence-guide.md) conserva el procedimiento de desarrollo con Java local y PostgreSQL en Docker. Esta guía cubre la conexión entre contenedores.

## Requisitos de configuración

| Elemento | Requisito del módulo |
| --- | --- |
| Aplicación | Imagen construida con `modules/05-siem/Dockerfile`; Java 21; HTTP interno en el puerto `80`. |
| Perfil Spring | `SPRING_PROFILES_ACTIVE=persistence`. Sin él no se registra el repositorio PostgreSQL y un evento válido responde 503. |
| PostgreSQL | `postgres:17-alpine`, versión ya utilizada por [compose.storage.yml](../compose.storage.yml). No requiere instalar PostgreSQL en el ordenador. |
| Base y usuario | Base `siem_bd` por defecto, usuario `siem`. El usuario está fijado en `application-persistence.properties`; no existe una variable propia `SIEM_DB_USER`. |
| Conexión | `SIEM_DB_URL=jdbc:postgresql://siem-db:5432/siem_bd` con el nombre de servicio propuesto. Dentro del contenedor no se utiliza el loopback del ordenador ni el puerto local `5433`. |
| Contraseña | `SIEM_DB_PASSWORD` no vacía, coherente con la contraseña del usuario en PostgreSQL. No se versiona ni se incluye en evidencias. |
| Datos | Volumen nombrado en `/var/lib/postgresql/data`. Conservar el mismo proyecto Compose y volumen para reutilizar la base. |
| Inicialización | Montar `modules/05-siem/db/init` en `/docker-entrypoint-initdb.d:ro`, con la ruta resuelta desde la raíz del monorepo. |
| Red | SIEM y PostgreSQL comparten una red. La base no necesita publicar un puerto en el ordenador ni conectarse a las redes de productores. |
| Arranque | PostgreSQL debe estar disponible antes de iniciar el SIEM con `persistence`; un fallo inicial del pool puede impedir que la API arranque. |

Fuentes de configuración: [application.properties](../src/main/resources/application.properties), [application-persistence.properties](../src/main/resources/application-persistence.properties), [EventPersistenceConfiguration](../src/main/java/com/ciberurjc/siem/config/EventPersistenceConfiguration.java) y [Dockerfile](../Dockerfile).

### Variables y secretos

| Variable | Destinatario | Uso |
| --- | --- | --- |
| `SPRING_PROFILES_ACTIVE` | SIEM | Activar `persistence`. |
| `SIEM_DB_URL` | SIEM | URL JDBC interna completa. Debe indicar la base realmente inicializada. |
| `SIEM_DB_PASSWORD` | SIEM y configuración de PostgreSQL | El SIEM la lee directamente; Compose puede usarla para establecer `POSTGRES_PASSWORD` en la base. |
| `SIEM_DB_NAME` | Interpolación Compose | Elegir la base al inicializar PostgreSQL y componer la URL. Por defecto `siem_bd`. No renombra una base existente. |
| `SERVER_PORT` | SIEM | La imagen ya establece `80`; conservarlo en el despliegue común. |

`SIEM_DB_PORT` pertenece al acceso local del Compose de almacenamiento; no cambia el puerto interno `5432`. `SIEM_EVENTS_MAX_BODY_BYTES` y `SIEM_ALERTS_MAX_STORED` son ajustes opcionales de la aplicación, con valores predeterminados `65536` y `10000`.

El archivo de variables y los valores secretos se mantienen fuera del repositorio. Que una variable exista en un archivo no la introduce automáticamente en el contenedor: G7 debe declararla en el servicio o proporcionar el mecanismo equivalente. `SIEM_DB_PASSWORD_FILE` no está implementada por el SIEM; montar un secreto como archivo no basta para que la aplicación lo lea.

Queda por acordar con G1 y G7 el suministro y la rotación de la contraseña. La implementación actual no consulta automáticamente el gestor de secretos de G1. Cambiar `POSTGRES_PASSWORD` al recrear un contenedor tampoco cambia la contraseña de una base ya inicializada.

## Configuración de referencia de PostgreSQL

Este fragmento recoge la parte de almacenamiento del Compose raíz. La configuración del proyecto conserva los servicios y redes de Identidad y de los productores. Para autenticar peticiones, el SIEM también necesita la URL interna de Identidad en `IDENTITY_URL`.

```yaml
services:
  siem:
    environment:
      SPRING_PROFILES_ACTIVE: persistence
      SIEM_DB_URL: jdbc:postgresql://siem-db:5432/${SIEM_DB_NAME:-siem_bd}
      SIEM_DB_PASSWORD: ${SIEM_DB_PASSWORD:?Set SIEM_DB_PASSWORD}
    depends_on:
      siem-db:
        condition: service_healthy
    networks:
      - ciberurjc
      - honeypot-siem
      - siem-bd

  siem-db:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: ${SIEM_DB_NAME:-siem_bd}
      POSTGRES_USER: siem
      POSTGRES_PASSWORD: ${SIEM_DB_PASSWORD:?Set SIEM_DB_PASSWORD}
    volumes:
      - siem-postgres-data:/var/lib/postgresql/data
      - ./modules/05-siem/db/init:/docker-entrypoint-initdb.d:ro
    networks:
      - siem-bd
    healthcheck:
      test: ["CMD-SHELL", 'pg_isready -U "$${POSTGRES_USER}" -d "$${POSTGRES_DB}"']
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

networks:
  siem-bd:
    internal: true

volumes:
  siem-postgres-data:
```

`pg_isready` comprueba disponibilidad de PostgreSQL, pero no acredita que el esquema esté completo ni que las credenciales JDBC sean correctas. G7 debe contemplar el tiempo de inicialización al definir la espera del primer arranque; la aceptación incluye una consulta al esquema y una escritura real a través del SIEM.

El volumen del Compose de desarrollo y el del Compose común pueden tener nombres efectivos distintos por el prefijo de proyecto. No se presupone una transferencia automática de datos entre ambos.

## Esquema y migraciones

| Orden | Script | Resultado |
| --- | --- | --- |
| 001 | [001-create-events.sql](../db/init/001-create-events.sql) | Tabla `events`, clave primaria `(source, event_id)`, `occurred_at` en `TIMESTAMPTZ`, `details` en `JSONB` e índices. |
| 002 | [002-add-original-timestamp.sql](../db/init/002-add-original-timestamp.sql) | Columna `original_timestamp` para conservar el texto de fecha recibido. |
| 003 | [003-allow-info-severity.sql](../db/init/003-allow-info-severity.sql) | Catálogo de severidad `info`, `low`, `medium`, `high`, `critical`, compatible con bases anteriores. |
| 004 | [004-allow-pentesting-source.sql](../db/init/004-allow-pentesting-source.sql) | Catálogo de origen `ids`, `honeypot`, `scanner`, `pentesting`. |

En un volumen vacío se ejecutan los cuatro scripts en orden durante la inicialización de la imagen. El script 001 por sí solo no incorpora la columna de 002 ni el origen `pentesting` de 004. El SIEM no ejecuta estas migraciones al arrancar.

En una base existente, montar el directorio no vuelve a ejecutar los scripts. Antes de actualizar: detener la ingesta en una ventana acordada, guardar una copia de seguridad fuera del repositorio, identificar la versión del esquema y aplicar con `ON_ERROR_STOP=1` las migraciones que falten, en orden. El procedimiento SQL y la conservación de datos se detallan en la [guía de persistencia](sem67-persistence-guide.md). No borrar volúmenes para resolver una migración o una contraseña incorrecta.

La tabla debe disponer de `original_timestamp`, la clave compuesta y ambos catálogos actualizados antes de habilitar los productores. Una migración fallida requiere revisar el esquema y el error; no continuar con la aplicación como si se hubiera completado. La recuperación de datos se basa en la copia de seguridad y el volumen conservado, no en una migración inversa automática.

## Procedimiento de aceptación del despliegue

Ejecuta la prueba desde la raíz del monorepo en Zsh, sobre la revisión de entrega y en un entorno acordado. Los comandos usan `identidad`, `siem-db` y `siem`, la base `siem_bd` y el puerto local del SIEM `8005`.

El archivo externo del ejemplo debe existir y contener las variables de despliegue correspondientes. No se muestran sus valores ni se vuelca la configuración expandida en evidencias.

```zsh
export SEM128_ENV_FILE="$HOME/.config/ciberurjc/sprint3.env"
docker compose --env-file "$SEM128_ENV_FILE" config --quiet
docker compose --env-file "$SEM128_ENV_FILE" up --build -d --wait identidad siem-db siem
docker compose --env-file "$SEM128_ENV_FILE" ps siem-db siem
docker compose --env-file "$SEM128_ENV_FILE" exec -T siem-db psql -X -U siem -d siem_bd -v ON_ERROR_STOP=1 -c '\d events'
curl --fail --silent --show-error http://localhost:8005/health
```

### Evento de prueba y reenvío

Obtén en Identidad un Bearer de `svc-escaner` para publicar y un Bearer de una cuenta `analista` para consultar. Disponlos en `SEM128_PRODUCER_TOKEN` y `SEM128_READER_TOKEN` en tu sesión local. Con el contrato `0.5.0`, la publicación requiere que la cuenta coincida con el `source` del evento.

El siguiente bloque adapta el ejemplo informativo del Escáner con un identificador y una fecha de prueba en un directorio temporal externo al repositorio. Conserva el mismo archivo para el reenvío.

```zsh
export SEM128_PROBE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/siem-sem128.XXXXXX")
export SEM128_EVENT_ID="SEM128-$(python3 -c 'import uuid; print(uuid.uuid4())')"
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

fixture = Path("modules/05-siem/contract/examples/grupo_4_scanner_info.json")
event = json.loads(fixture.read_text(encoding="utf-8"))
event["event_id"] = os.environ["SEM128_EVENT_ID"]
event["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
Path(os.environ["SEM128_PROBE_DIR"], "event.json").write_text(
    json.dumps(event), encoding="utf-8"
)
print(event["event_id"])
PY
curl --fail --silent --show-error --write-out '\nHTTP %{http_code}\n' -H "Authorization: Bearer ${SEM128_PRODUCER_TOKEN:?Set SEM128_PRODUCER_TOKEN}" -H 'Content-Type: application/json' --data-binary @"$SEM128_PROBE_DIR/event.json" http://localhost:8005/events
curl --fail --silent --show-error --write-out '\nHTTP %{http_code}\n' -H "Authorization: Bearer ${SEM128_PRODUCER_TOKEN:?Set SEM128_PRODUCER_TOKEN}" -H 'Content-Type: application/json' --data-binary @"$SEM128_PROBE_DIR/event.json" http://localhost:8005/events
```

Ambas respuestas deben ser HTTP 200, con `status: success` y el mismo `event_id` generado. Un timeout no demuestra ausencia de almacenamiento: se reenvía el mismo archivo, sin regenerar fecha ni identidad. Un conflicto 409 no se resuelve sobrescribiendo o borrando el evento previo.

### Consulta, identidad y conservación

```zsh
curl --fail --silent --show-error -H "Authorization: Bearer ${SEM128_READER_TOKEN:?Set SEM128_READER_TOKEN}" 'http://localhost:8005/events?limit=500&offset=0'
curl --fail --silent --show-error -H "Authorization: Bearer ${SEM128_READER_TOKEN:?Set SEM128_READER_TOKEN}" http://localhost:8005/alerts
docker compose --env-file "$SEM128_ENV_FILE" exec -T siem-db psql -X -U siem -d siem_bd -v ON_ERROR_STOP=1 -v event_id="$SEM128_EVENT_ID" <<'SQL'
SELECT count(*) AS matching_events
FROM events WHERE source = 'scanner' AND event_id = :'event_id';
SELECT event_id, source, severity, original_timestamp, details
FROM events WHERE source = 'scanner' AND event_id = :'event_id';
SQL
```

Buscar el identificador en `events`; si no está en la primera página, seguir `next` hasta localizarlo. La fila SQL debe ser única y conservar `info`, fecha y detalles del archivo. El evento informativo no debe tener una alerta asociada. Para verificarlo, buscar su `event_id` y `source` en el listado de alertas; no se exige que el resto de la colección esté vacío.

En el entorno de verificación, conservar el proyecto, el archivo de variables y el volumen, detener el SIEM y recrear solo el contenedor PostgreSQL:

```zsh
docker compose --env-file "$SEM128_ENV_FILE" stop siem siem-db
docker compose --env-file "$SEM128_ENV_FILE" rm -f siem-db
docker compose --env-file "$SEM128_ENV_FILE" up -d --wait identidad siem-db siem
```

Repetir las consultas HTTP y SQL anteriores. El evento debe seguir en el histórico y continuar ocupando una sola fila. Las alertas actuales viven en memoria y se pierden al reiniciar el SIEM; este procedimiento no acredita persistencia de alertas ni integración SOAR/Dashboard.

### Resultado y cierre de la prueba

| Comprobación | Resultado exigido |
| --- | --- |
| Arranque y esquema | API disponible, tabla completa y sin errores de conexión o migración. |
| Ingesta | HTTP 200 y acuse con el identificador enviado. |
| Reenvío idéntico | HTTP 200 y una fila por `(source, event_id)`. |
| Histórico | Mismo evento, fecha, severidad y `details`. |
| Evento informativo | Guardado en el histórico sin crear alerta. |
| Recreación PostgreSQL | Evento conservado en el mismo volumen y recuperable desde la API. |

Registrar versiones de ambos equipos, configuración sin secretos, respuestas y resultados de las consultas. Un `GET /health` 200 aislado no demuestra recepción ni persistencia. Una caída de PostgreSQL durante la ingesta debe producir 503; su ensayo controlado se acuerda aparte para no interrumpir a otros grupos. El [ejecutor aislado de almacenamiento](sem66-storage-tests.md) ya cubre fallos, recuperación y migraciones en sus propios recursos.

Si los servicios se arrancaron exclusivamente para esta comprobación, detenerlos al finalizar, también cuando una comprobación falle:

```zsh
docker compose --env-file "$SEM128_ENV_FILE" stop siem siem-db identidad
docker compose --env-file "$SEM128_ENV_FILE" ps siem siem-db identidad
unset SEM128_EVENT_ID SEM128_PROBE_DIR SEM128_ENV_FILE SEM128_PRODUCER_TOKEN SEM128_READER_TOKEN
```

Conservar o retirar los archivos temporales según las evidencias necesarias. No utilizar `down -v` ni eliminar volúmenes compartidos. Si Docker Desktop se abrió exclusivamente para la prueba y no hay otros contenedores o trabajos activos, cerrarlo al terminar. En un despliegue compartido, coordinar la parada con G7.

## Decisiones y validaciones pendientes

| Punto | Estado y siguiente comprobación |
| --- | --- |
| Nombres, red, volumen y política de arranque | Configuración incorporada por la #96. Verificar en el SHA común acordado. |
| Contraseña y rotación | Acordar el suministro con G1/G7 y su aplicación a una base existente. |
| Autenticación de la API | La candidata `0.5.0` usa Identidad y la [matriz de permisos](../contract/roles-permissions.md). Confirmar los mapeos de los productores en el Compose de entrega. |
| Integración común | La prueba local de [SEM-131](sem131-compose-verification.md) pasó con el mapeo de la #132. Queda repetirla en el Compose común acordado. |
| Persistencia de alertas | Fuera de este documento; el almacén actual sigue siendo en memoria. |

Los productores deben utilizar el destino interno `http://siem:80/events`; su configuración, credenciales y publicación efectiva se contrastan con cada grupo. Esta guía no modifica sus módulos ni sustituye la verificación de contratos.
