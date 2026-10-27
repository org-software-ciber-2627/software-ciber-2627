# SIEM · Sprint 2

Servidor Java 21 y Spring Boot 4.1.1 para recibir eventos, persistirlos en PostgreSQL y consultar alertas de ejemplo.

Consulta la [guía de configuración y persistencia](docs/sem67-persistence-guide.md), las [pruebas de almacenamiento](docs/sem66-storage-tests.md) y la [verificación manual](docs/sem67-acceptance-check.md).

## Alcance

Con el perfil Spring `persistence`, `POST /events` valida y almacena el evento antes de confirmar la recepción. La clave primaria `(source, event_id)` evita duplicar eventos: el reenvío con el mismo contenido recibe 200 y el mismo identificador con otro contenido recibe 409. Sin almacenamiento disponible, la ingesta responde 503. La validación existente conserva 400 y 415.

`GET /alerts` y `GET /alerts/{id}` usan tres alertas estáticas. Ingerir un evento no modifica esa lista ni genera correlaciones. La API no autentica productores.

## Arranque sin persistencia

Este modo comprueba el servidor y las alertas estáticas. No activa el perfil `persistence`; por eso un evento válido responde 503.

Desde la raíz del repositorio:

```bash
docker compose up --build -d siem
docker compose ps siem
curl -f http://localhost:8005/health
```

Acceso local: `http://localhost:8005`. La red Docker compartida usa `http://siem:80`.

## API

| Ruta | Resultado |
| --- | --- |
| `GET /health` | 200 con estado del servicio |
| `POST /events` | 200 al guardar o reconocer un reenvío idéntico; 400 evento inválido; 409 conflicto de identificador; 415 tipo de contenido no admitido; 503 almacenamiento no disponible |
| `GET /alerts` | 200 con tres alertas de ejemplo |
| `GET /alerts/{id}` | 200 con una alerta o 404 si no existe |

El contrato histórico del mock está en `contract/openapi.json`. El comportamiento de persistencia se describe en [SEM-65](contract/sem65-ingestion-proposal.md); no se debe interpretar el OpenAPI histórico como especificación de las respuestas de persistencia.

Los datos que PostgreSQL no puede representar, como caracteres nulos, Unicode incompleto o valores fuera de su rango admitido, se rechazan con 400 sin insertar. Los fallos del almacenamiento responden con un error genérico y 503.

```bash
curl -i -H 'Content-Type: application/json' --data-binary @modules/05-siem/contract/examples/grupo_3_honeypot.json http://localhost:8005/events
curl -i http://localhost:8005/alerts
curl -i http://localhost:8005/alerts/SIEM-ALERT-EJEMPLO-003
```

## Base de datos

Desde la raíz del repositorio, copia `.env.example` a `.env` y define `SIEM_DB_PASSWORD` con una contraseña local. El `.env` está excluido de Git. Arranca PostgreSQL:

```bash
docker compose --profile siem-db up -d --wait siem-db
docker compose ps siem-db
```

La base de datos es `siem_bd` y el usuario es `siem`. El perfil `siem-db` es opcional. PostgreSQL se publica solo en `127.0.0.1:5433`; `SIEM_DB_PORT` permite cambiar el puerto local. Dentro de la red Docker, el host y puerto son `siem-db:5432`.

El esquema crea `events` desde `db/init/001-create-events.sql`. Su clave primaria es `(source, event_id)`, `occurred_at` conserva el instante UTC y `details` se almacena como JSONB. El segundo script añade `original_timestamp` para conservar el texto completo del timestamp recibido. Los scripts de inicialización se aplican automáticamente solo a un volumen vacío; en una base ya inicializada hay que aplicar la migración 002.

El volumen `siem-postgres-data` conserva los datos al recrear el contenedor. No uses `docker compose down -v` si quieres conservarlos.

## Arranque Java con persistencia

La aplicación Java no carga automáticamente el `.env` de Compose. Exporta las variables necesarias y arranca PostgreSQL como se indica en la [guía de persistencia](docs/sem67-persistence-guide.md). El perfil requiere que PostgreSQL esté disponible al iniciar.

Desde `modules/05-siem`:

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=persistence -Dspring-boot.run.arguments=--server.address=127.0.0.1
```

Variables: `SIEM_DB_PASSWORD` (obligatoria), `SIEM_DB_NAME` (por defecto `siem_bd`), `SIEM_DB_PORT` (por defecto `5433`) y `SIEM_DB_URL` (opcional). La aplicación escucha en `127.0.0.1` con puerto `SERVER_PORT` o `8005`.

## Comprobaciones

Desde `modules/05-siem`, ejecuta las pruebas Java:

```bash
./mvnw clean verify
```

Para comprobar también PostgreSQL real, migraciones, recuperación, reenvíos y persistencia del volumen, usa el [ejecutor aislado SEM-66](docs/sem66-storage-tests.md). La validación del OpenAPI histórico requiere `jsonschema>=4,<5`:

```bash
python3 scripts/verify-contract.py
```

Los logs de ingesta no incluyen `credential` ni `details`; los ejemplos de `contract/examples/` son datos ficticios de laboratorio.
