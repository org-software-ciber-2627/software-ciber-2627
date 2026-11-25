# SIEM · Sprint 2

Servidor Java 21 y Spring Boot 4.1.1 para recibir eventos, persistirlos en PostgreSQL, consultar su histórico paginado y consultar alertas generadas.

Consulta la [guía de configuración y persistencia](docs/sem67-persistence-guide.md), las [pruebas de almacenamiento](docs/sem66-storage-tests.md) y la [verificación manual](docs/sem67-acceptance-check.md).

## Alcance

Con el perfil Spring `persistence`, `POST /events` valida y almacena el evento antes de confirmar la recepción. La clave primaria `(source, event_id)` evita duplicar eventos: el reenvío con el mismo contenido recibe 200 y el mismo identificador con otro contenido recibe 409. Sin almacenamiento disponible, la ingesta responde 503. La validación conserva 400 y 415. El límite de cuerpo se indica con 413.

La [especificación Escáner → SIEM](contract/scanner-events.md) define el formato de publicación. El catálogo común de eventos admite `info`, `low`, `medium`, `high` y `critical`. Para bases existentes, aplica la migración `003-allow-info-severity.sql` antes de enviar eventos informativos. Las [pruebas de compatibilidad](docs/scanner-events-tests.md) verifican entradas sintéticas; la [prueba de integración real](docs/scanner-integration.md) ejecuta el productor y contrasta entrega y almacenamiento.

`GET /events` consulta los eventos realmente almacenados. Devuelve `events`, `next_offset` y `next`; la colección vacía es un 200 y la ausencia de almacenamiento un 503. Consulta el [contrato del histórico](contract/history-events.md) y su [matriz de pruebas](docs/history-events-tests.md).

`GET /alerts` y `GET /alerts/{id}` consultan un mismo almacén de alertas en memoria. Los eventos `info` se almacenan sin generar alertas. Los demás eventos pasan por el conversor y P004 usa el [evaluador de intentos repetidos](docs/sem29-deteccion-intentos-fallidos.md). El almacén de alertas se vacía al reiniciar.

## Arranque sin persistencia

Este modo comprueba el servidor y el listado inicialmente vacío. No activa el perfil `persistence`; por eso un evento válido responde 503.

Desde la raíz del repositorio:

```zsh
docker compose up --build -d siem
docker compose ps siem
curl -f http://localhost:8005/health
```

Acceso local: `http://localhost:8005`. La red Docker compartida usa `http://siem:80`.

## API

| Ruta | Resultado |
| --- | --- |
| `GET /health` | 200 con estado del servicio |
| `POST /events` | 200 al guardar o reconocer un reenvío idéntico; 400 evento inválido; 409 conflicto de identificador; 413 cuerpo demasiado grande; 415 tipo de contenido no admitido; 503 PostgreSQL no disponible; 507 almacén de alertas lleno |
| `GET /events?limit=100&offset=0` | 200 con histórico paginado; 400 consulta inválida; 503 almacenamiento no disponible/timeout; 500 error inesperado |
| `GET /alerts` | 200 con `{"alerts":[]}` si está vacío, 503/500 ante fallo de consulta |
| `GET /alerts/{id}` | 200 con una alerta o 404 si no existe, 503/500 ante fallo de consulta |

El [OpenAPI vigente de esta rama](contract/openapi.json) documenta ingesta persistente, histórico y alertas reales. La semántica detallada de ingesta está en [SEM-65](contract/sem65-ingestion-proposal.md) y la consulta en [history-events.md](contract/history-events.md).

Los datos que PostgreSQL no puede representar, como caracteres nulos, Unicode incompleto o valores fuera de su rango admitido, se rechazan con 400 sin insertar. Los fallos del almacenamiento responden con un error genérico y 503.

```zsh
curl -i -H 'Content-Type: application/json' --data-binary @modules/05-siem/contract/examples/grupo_3_honeypot.json http://localhost:8005/events
curl -i 'http://localhost:8005/events?limit=2&offset=0'
curl -i http://localhost:8005/alerts
curl -i http://localhost:8005/alerts/ALERT_ID
```

## Navegación del histórico

`limit` vale 100 por defecto y admite de 1 a 500; `offset` vale 0. El orden es `occurred_at DESC, source ASC, event_id ASC`. Una página contiene como máximo `limit` eventos; `next` conserva ese límite y permite pedir la siguiente página resolviendo el enlace contra el origen de la API. Al terminar, `next` y `next_offset` son nulos. No hay total ni filtros de HU11.

```json
{"events": [], "next_offset": null, "next": null}
```

Por ejemplo, si la respuesta contiene `next: "/events?limit=2&offset=2"`, la siguiente petición es:

```zsh
curl -i 'http://localhost:8005/events?limit=2&offset=2'
```

Los parámetros vacíos, duplicados, desconocidos o inválidos producen 400. No se envían secretos en la URL. La API no implementa IAM. OFFSET no conserva una instantánea: inserciones concurrentes pueden causar repeticiones u omisiones y los desplazamientos grandes pueden ser costosos. El timeout JDBC de lectura es de cinco segundos; no es una garantía del tiempo total de respuesta.

## Base de datos

Desde la raíz del repositorio, define y exporta `SIEM_DB_PASSWORD` como indica la [guía de persistencia](docs/sem67-persistence-guide.md). Arranca PostgreSQL con el Compose del módulo:

```zsh
docker compose --env-file /dev/null -f modules/05-siem/compose.storage.yml up -d --wait siem-db
docker compose --env-file /dev/null -f modules/05-siem/compose.storage.yml ps siem-db
```

La base de datos es `siem_bd` y el usuario es `siem`. PostgreSQL se publica solo en `127.0.0.1:5433`; `SIEM_DB_PORT` permite cambiar el puerto local. Este Compose proporciona la base de datos para el SIEM local. El Compose común arranca el servicio sin el perfil Java de persistencia.

El esquema crea `events` desde `db/init/001-create-events.sql`. Su clave primaria es `(source, event_id)`, `occurred_at` conserva el instante UTC y `details` se almacena como JSONB. El segundo script añade `original_timestamp` para conservar el texto completo del timestamp recibido. El tercero permite la severidad `info` sin alterar los eventos existentes. El cuarto sustituye la restricción de `source` para aceptar también `pentesting` (G8). Los scripts de inicialización se aplican automáticamente solo a un volumen vacío; en una base ya inicializada hay que aplicar las migraciones que falten (002 para el timestamp, 003 para `info` y 004 para `pentesting`).

El volumen `siem-postgres-data` conserva los datos al recrear el contenedor. No uses `docker compose down -v` si quieres conservarlos.

## Arranque Java con persistencia

La aplicación Java no carga automáticamente el `.env` de Compose. Exporta las variables necesarias y arranca PostgreSQL como se indica en la [guía de persistencia](docs/sem67-persistence-guide.md). El perfil requiere que PostgreSQL esté disponible al iniciar.

Desde `modules/05-siem`:

```zsh
./mvnw spring-boot:run -Dspring-boot.run.profiles=persistence -Dspring-boot.run.arguments=--server.address=127.0.0.1
```

Variables: `SIEM_DB_PASSWORD` (obligatoria), `SIEM_DB_NAME` (por defecto `siem_bd`), `SIEM_DB_PORT` (por defecto `5433`) y `SIEM_DB_URL` (opcional). El comando de arranque limita la escucha a `127.0.0.1`, con puerto `SERVER_PORT` o `8005`.

## Comprobaciones

Desde `modules/05-siem`, ejecuta las pruebas Java:

```zsh
./mvnw clean verify
```

Para comprobar también PostgreSQL real, migraciones, recuperación, reenvíos y persistencia del volumen, usa el [ejecutor aislado SEM-66](docs/sem66-storage-tests.md). La validación de los contratos requiere `jsonschema>=4,<5`:

```zsh
python3 -B scripts/verify-contract.py
```

La comprobación completa de HU10 y de respuestas reales contra OpenAPI se ejecuta con `test-storage.py --verify-contract`, usando un entorno temporal con las dependencias de `scripts/requirements.txt`. El [procedimiento del histórico](docs/history-events-tests.md) distingue pruebas locales e integración posterior.

Los logs de ingesta no incluyen `credential` ni `details`; los ejemplos de `contract/examples/` son datos ficticios de laboratorio.
