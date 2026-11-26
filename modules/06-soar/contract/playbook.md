# Contrato del playbook de fuerza bruta — HU14

## Objetivo

Ejecutar la respuesta automática de un incidente de tipo `fuerza_bruta` (honeypot) o
`brute_force` (IDS) que HU13 ha marcado como automatizable (`playbook = "brute_force"`).

## Entrada: `BruteForcePlaybookInput`

Se construye con `BruteForcePlaybookInput.from_incident(incident)` a partir del `Incident` único.
Si `event_type` no es `fuerza_bruta` ni `brute_force`, lanza `ValueError`.

| Campo | Origen |
|---|---|
| `incident_id`, `source_ip`, `target_ip` | El incidente |
| `service` | `details.service` (por defecto `unknown`) |
| `username`, `usernames` | Honeypot: `details.username`; IDS: `details.usernames` (lista). `username` es el primero para compatibilidad |
| `failed_attempts` | IDS: `details.attempts`; si falta, `details.failed_attempts`; si falta, `1`. Honeypot: `details.failed_attempts` y, si falta, `1` |
| `event_type`, `severity`, `priority` | El incidente |
| `detected_at` | `created_at` del incidente |

## Salida: `BruteForcePlaybookOutput`

```json
{
  "execution_id": "3f0c...",
  "incident_id": "INC-4F9A2C",
  "playbook": "brute_force",
  "status": "COMPLETED",
  "actions_taken": [
    {"action_name": "block_ip", "target": "192.168.1.50", "status": "success", "details": "IP 192.168.1.50 bloqueada"},
    {"action_name": "notify", "target": "group7", "status": "success", "details": "Incidente notificado al grupo 7 (HTTP 200)"}
  ],
  "executed_at": "2026-11-03T12:00:00+00:00",
  "summary": "block_ip=success, notify=success"
}
```

- Las acciones se ejecutan en este orden: `block_ip` y después `notify`. Si una falla, las demás se ejecutan igualmente.
- `actions_taken[].status`: `success`, `failed` o `skipped`.
- `status`: `COMPLETED` si todas las acciones tienen éxito, `FAILED` si ninguna, `PARTIAL` si hay mezcla.
  Por ejemplo, con la IP bloqueada y `GROUP7_NOTIFY_URL` sin configurar el estado es `PARTIAL`.
- `executed_at` siempre en UTC con zona horaria.

## Acciones por Sprint

| Sprint | Acciones | Ejecuta |
|---|---|---|
| Sprint 2 | `notify` | Módulo 6 |
| Sprint 3 (HU19) | `block_ip`: lista negra simulada de IPs (ver `blacklist.md`) | Módulo 6 |
| Backlog futuro | `disable_account` y el bloqueo real en Identidad | Equipo 1 (acordado el 24/11) |

## Acción `block_ip` (HU19.2)

Mete la IP de origen del incidente (`source_ip`) en la lista negra **simulada** del SOAR con
`BlacklistService.block(source_ip, incident_id, reason)`, donde `reason` es el motivo de la decisión
de HU13. No se bloquea la IP en ningún sistema real. `target` es la IP.

| Caso | Estado de la acción | `details` |
|---|---|---|
| `blocked`: IP nueva, se guarda | `success` | `IP 192.168.1.50 bloqueada` |
| `already_blocked`: la IP ya estaba en la lista | `success` | `La IP 192.168.1.50 ya estaba bloqueada: la IP ya está contenida` |
| `excluded`: loopback, `0.0.0.0` o red de `BLACKLIST_EXCLUDED_NETWORKS` | `skipped` | `La IP 127.0.0.1 no se puede bloquear: es una IP protegida` |
| `invalid_ip`: la IP no es válida | `failed` | `IP no válida: '...'` |
| Lista negra no configurada en el `PlaybookService` | `skipped` | `Lista negra no configurada` |
| La lista negra lanza un error | `failed` | `No se pudo bloquear la IP: <error>`; `notify` se ejecuta igualmente |

`already_blocked` es `success` porque la IP ya está contenida. La lista negra se conecta al flujo de
sondeo en HU19.3; hasta entonces el pipeline no la configura y `block_ip` queda en `skipped`.

## Acción `notify`

Envía el incidente al grupo 7 (dashboard) con `POST` JSON a la URL de `GROUP7_NOTIFY_URL`, con timeout de 5 s.

| Caso | Estado de la acción |
|---|---|
| `GROUP7_NOTIFY_URL` vacía o sin definir | `skipped` (no se hace ninguna petición) |
| Respuesta 2xx/3xx | `success` |
| Respuesta >= 400, error de red o timeout | `failed`, con el error en `details` |

Cuerpo enviado (**provisional, pendiente de confirmar con el grupo 7**):

```json
{
  "incident_id": "INC-4F9A2C",
  "event_type": "fuerza_bruta",
  "severity": "medium",
  "priority": "medium",
  "source_ip": "192.168.1.50",
  "service": "ssh",
  "username": "root",
  "usernames": ["root"],
  "failed_attempts": 1,
  "playbook": "brute_force",
  "reason": "Incidente compatible con automatizacion",
  "detected_at": "2026-11-03T11:59:58+00:00"
}
```

## Efectos en el flujo

- Cada acción se registra como una respuesta ejecutada (HU15, ver `executed_response.md`).
- Si alguna acción tiene éxito, el incidente pasa de `open` a `in_progress` (HU6) con la justificación
  `Respuesta automática ejecutada: <acciones>` (solo las que tienen éxito, por ejemplo `block_ip, notify`).
  Si todas fallan o se omiten, sigue en `open`.
- Si el incidente ya tiene respuestas registradas, el playbook no se vuelve a ejecutar.
