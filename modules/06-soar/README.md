# Módulo 6 · Gestor de incidentes (SOAR ligero)

- **Equipo propietario:** `equipo-06-soar`
- **Puerto:** `8006`

## Qué expone
Registra incidentes a partir de las alertas del SIEM, evita procesar dos veces
la misma alerta y ejecuta la respuesta automática de los incidentes de fuerza bruta.
- `GET /health`
- `GET /incidents` — incidentes con prioridad, estado, decisión de automatización y respuestas.
- `GET /incidents/{incident_id}/responses` — respuestas ejecutadas de un incidente (HU15).
- `GET /incidents/{incident_id}/history` — historial de cambios de estado, con quién los hizo (HU7).
- `GET /metrics` — MTTD, MTTR y número de incidentes totales y cerrados (HU16 y HU18).
- `GET /blacklist` — IPs de la lista negra simulada (HU19).
- `POST /incidents/{incident_id}/status` — cambio de estado con justificación (HU6).
- `POST /poll` — consulta `GET /alerts` del SIEM y procesa las alertas nuevas.

El detalle de cada endpoint está en `contract/README.md`.

## Qué consume
- `GET /alerts` del SIEM, con `Authorization: Bearer <token>` si la autenticación está configurada (HU21).
- `POST /auth/login` del Módulo 1 (Identidad) con la cuenta de servicio `svc-soar`, para obtener ese token.
- `POST` a `GROUP7_NOTIFY_URL` (grupo 7) para la acción `notify` del playbook de fuerza bruta.

## Flujo de una alerta

`src/soar/services/pipeline.py` procesa cada alerta en este orden:

1. Normalización contra el contrato del SIEM (`soar/normalization`). Si no cumple, se cuenta como `rejected`.
2. Idempotencia con la tabla `incidents`. Si ya existe, se cuenta como `ignored`.
3. Se guarda el `Incident` normalizado y se calcula su prioridad (HU5).
4. Se decide si es automatizable (HU13).
5. Si lo es y no tiene respuestas previas, se ejecuta el playbook (HU14): primero `block_ip`, que
   mete la IP de origen en la lista negra simulada (HU19), y después `notify`. Se registra cada
   respuesta (HU15) y, si alguna acción tiene éxito, el incidente pasa a `in_progress` (HU6).
6. Si `block_ip` tiene éxito, el incidente pasa además a `contained` (HU19). Los dos cambios
   automáticos se registran con `changed_by = "soar-automation"`.

## Persistencia e idempotencia

El servicio usa SQLite en `DATABASE_PATH` (por defecto `/data/soar.db`), con estas tablas:

| Tabla | Contenido |
|---|---|
| `incidents` | Alerta cruda e idempotencia (Sprint 1) |
| `soar_incidents` | `Incident` normalizado |
| `status_history` | Cambios de estado (HU6) |
| `executed_responses` | Respuestas ejecutadas (HU15) |
| `ip_blacklist` | Lista negra simulada de IPs, con la IP como clave única (HU19) |

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
| `AUTH_URL` (o `IDENTITY_URL`) | vacía | URL base del Módulo 1 (Identidad). Activa a la vez el token hacia el SIEM (HU21) y la autenticación de nuestros endpoints con `GET /auth/validate` (HU20). Vacía, no se envía token al SIEM y los endpoints quedan abiertos (con un `WARNING`) |
| `SOAR_SERVICE_USER` | `svc-soar` | Cuenta de servicio con la que el SOAR hace login |
| `SOAR_SERVICE_PASSWORD` | vacía | Contraseña de esa cuenta. Vacía, no se envía token al SIEM. Nunca en el repositorio |
| `BLACKLIST_EXCLUDED_NETWORKS` | vacía | Redes que nunca se meten en la lista negra, separadas por comas (p. ej. la subred del docker-compose). Loopback y `0.0.0.0` se excluyen siempre |
| `SOAR_AUTH_RETRY_SECONDS` | `300` | Segundos sin reintentar el login tras un `401` o `429` de Identidad, para no bloquear la cuenta |
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
