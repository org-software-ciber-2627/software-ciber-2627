# Contrato del playbook de fuerza bruta — HU14

## Objetivo

Ejecutar la respuesta automática de un incidente de tipo `fuerza_bruta` que HU13 ha marcado como
automatizable (`playbook = "brute_force"`).

## Entrada: `BruteForcePlaybookInput`

Se construye con `BruteForcePlaybookInput.from_incident(incident)` a partir del `Incident` único.
Si `event_type` no es `fuerza_bruta`, lanza `ValueError`.

| Campo | Origen |
|---|---|
| `incident_id`, `source_ip`, `target_ip` | El incidente |
| `service` | `details.service` (por defecto `unknown`) |
| `username` | `details.username` |
| `failed_attempts` | `details.failed_attempts` (por defecto `1`) |
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
    {"action_name": "notify", "target": "group7", "status": "success", "details": "Incidente notificado al grupo 7 (HTTP 200)"}
  ],
  "executed_at": "2026-11-03T12:00:00+00:00",
  "summary": "notify=success"
}
```

- `actions_taken[].status`: `success`, `failed` o `skipped`.
- `status`: `COMPLETED` si todas las acciones tienen éxito, `FAILED` si ninguna, `PARTIAL` si hay mezcla.
- `executed_at` siempre en UTC con zona horaria.

## Acciones por Sprint

| Sprint | Acciones | Ejecuta |
|---|---|---|
| Sprint 2 | `notify` | Módulo 6 |
| Sprint 3 (previsto) | `block_ip`, `disable_account` | Equipo 1 (módulo de identidad) |

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
  "playbook": "brute_force",
  "reason": "Incidente compatible con automatizacion",
  "detected_at": "2026-11-03T11:59:58+00:00"
}
```

## Efectos en el flujo

- Cada acción se registra como una respuesta ejecutada (HU15, ver `executed_response.md`).
- Si alguna acción tiene éxito, el incidente pasa de `open` a `in_progress` (HU6) con la justificación
  `Respuesta automática ejecutada: <acciones>`. Si todas fallan o se omiten, sigue en `open`.
- Si el incidente ya tiene respuestas registradas, el playbook no se vuelve a ejecutar.
