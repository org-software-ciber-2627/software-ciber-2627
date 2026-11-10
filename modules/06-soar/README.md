# Módulo 6 · Gestor de incidentes (SOAR ligero)

- **Equipo propietario:** `equipo-06-soar`
- **Puerto:** `8006`

## Qué expone
Registra incidentes a partir de las alertas del SIEM, evita procesar dos veces
la misma alerta y ejecuta la respuesta automática de los incidentes de fuerza bruta.
- `GET /health`
- `GET /incidents` — incidentes con prioridad, estado, decisión de automatización y respuestas.
- `GET /incidents/{incident_id}/responses` — respuestas ejecutadas de un incidente (HU15).
- `POST /incidents/{incident_id}/status` — cambio de estado con justificación (HU6).
- `POST /poll` — consulta `GET /alerts` del SIEM y procesa las alertas nuevas.

El detalle de cada endpoint está en `contract/README.md`.

## Qué consume
- `GET /alerts` del SIEM.
- `POST` a `GROUP7_NOTIFY_URL` (grupo 7) para la acción `notify` del playbook de fuerza bruta.

## Flujo de una alerta

`src/soar/services/pipeline.py` procesa cada alerta en este orden:

1. Normalización contra el contrato del SIEM (`soar/normalization`). Si no cumple, se cuenta como `rejected`.
2. Idempotencia con la tabla `incidents`. Si ya existe, se cuenta como `ignored`.
3. Se guarda el `Incident` normalizado y se calcula su prioridad (HU5).
4. Se decide si es automatizable (HU13).
5. Si lo es y no tiene respuestas previas, se ejecuta el playbook (HU14), se registra cada
   respuesta (HU15) y, si alguna acción tiene éxito, el incidente pasa a `in_progress` (HU6).

## Persistencia e idempotencia

El servicio usa SQLite en `DATABASE_PATH` (por defecto `/data/soar.db`), con estas tablas:

| Tabla | Contenido |
|---|---|
| `incidents` | Alerta cruda e idempotencia (Sprint 1) |
| `soar_incidents` | `Incident` normalizado |
| `status_history` | Cambios de estado (HU6) |
| `executed_responses` | Respuestas ejecutadas (HU15) |

Cada alerta se identifica por `alert_id`/`id`; si no existe, se calcula SHA-256 sobre
`IP_origen`, `tipo_evento` y `timestamp`. La columna `alert_key` tiene una
restricción `UNIQUE`, por lo que la deduplicación también es segura si llegan
peticiones concurrentes.

## Variables de entorno

| Variable | Por defecto | Uso |
|---|---|---|
| `SIEM_URL` (o `SIEM_API_URL`) | `http://siem:80` | URL base del SIEM |
| `DATABASE_PATH` | `/data/soar.db` | Fichero SQLite |
| `POLL_INTERVAL_SECONDS` (o `SOAR_POLLING_INTERVAL`) | `0` | Segundos entre sondeos; con `0` solo se sondea con `POST /poll` |
| `GROUP7_NOTIFY_URL` | vacía | URL del grupo 7 para `notify`; vacía, la acción queda `skipped` |
| `LOG_LEVEL` | `INFO` | Nivel de log |

## Tests

```bash
pip install -r requirements-mock.txt
python -m pytest
```

## Mock local del SIEM (Sprint 1)

Simulación local del servicio SIEM (Equipo 5) para desacoplar el desarrollo del SOAR y cumplir los criterios del Sprint 1.

### Arranque rápido con Python
```bash
pip install -r requirements-mock.txt
uvicorn mock_siem_server:app --port 8000 --reload
```
