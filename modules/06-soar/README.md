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

<<<<<<< HEAD
## Persistencia e idempotencia

El servicio usa SQLite en `DATABASE_PATH` (por defecto `/data/soar.db`). Cada
alerta se identifica por `alert_id`/`id`; si no existe, se calcula SHA-256 sobre
`IP_origen`, `tipo_evento` y `timestamp`. La columna `alert_key` tiene una
restricción `UNIQUE`, por lo que la deduplicación también es segura si llegan
peticiones concurrentes.

Para activar el sondeo periódico, estableced `POLL_INTERVAL_SECONDS` con un
valor mayor que cero. Con `0` (valor por defecto) el sondeo se dispara
manualmente mediante `POST /poll`.
=======
## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.

## Mock local del SIEM (Sprint 1)

Simulación local del servicio SIEM (Equipo 5) para desacoplar el desarrollo del SOAR y cumplir los criterios del Sprint 1.

### Arranque rápido con Python
```bash
pip install -r requirements-mock.txt
uvicorn mock_siem_server:app --port 8000 --reload
>>>>>>> origin/equipo-06-soar/SB-4-mock-alertas-siem
