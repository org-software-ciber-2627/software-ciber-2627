# Módulo 6 · Gestor de incidentes (SOAR ligero)

- **Equipo propietario:** `equipo-06-soar`
- **Puerto:** `8006`

## Qué expone
Registra incidentes a partir de las alertas del SIEM y evita procesar dos veces
la misma alerta.
- `GET /health`
- `GET /incidents`
- `POST /poll` — consulta `GET /alerts` del SIEM y registra solo alertas nuevas.

## Qué consume
- `GET /alerts` del SIEM.

## Persistencia e idempotencia

El servicio usa SQLite en `DATABASE_PATH` (por defecto `/data/soar.db`). Cada
alerta se identifica por `alert_id`/`id`; si no existe, se calcula SHA-256 sobre
`IP_origen`, `tipo_evento` y `timestamp`. La columna `alert_key` tiene una
restricción `UNIQUE`, por lo que la deduplicación también es segura si llegan
peticiones concurrentes.

Para activar el sondeo periódico, estableced `POLL_INTERVAL_SECONDS` con un
valor mayor que cero. Con `0` (valor por defecto) el sondeo se dispara
manualmente mediante `POST /poll`.
