# Contrato de respuestas ejecutadas del SOAR

Este documento define la estructura de una respuesta ejecutada por el módulo 6 (SOAR ligero).
Una respuesta ejecutada registra el resultado de una acción de un playbook sobre un incidente,
para poder consultarla y auditarla después.

## Modelo ExecutedResponse

```json
{
  "response_id": "RES-4F9A2C",
  "incident_id": "INC-001",
  "playbook": "brute_force",
  "action": "notify",
  "status": "success",
  "triggered_by": "automatic",
  "executed_at": "2026-10-27T12:00:05Z",
  "finished_at": "2026-10-27T12:00:06Z",
  "message": "Incidente notificado al grupo 7",
  "error": null,
  "details": {}
}
```

## Campos

| Campo | Tipo | Obligatorio | Descripción |
| --- | --- | --- | --- |
| `response_id` | string | Sí (se genera) | Identificador único de la respuesta, formato `RES-XXXXXX` |
| `incident_id` | string | Sí | Identificador del incidente sobre el que se ejecuta la respuesta |
| `playbook` | string | Sí | Playbook que generó la respuesta (mismo valor que `AutomationDecision.playbook`) |
| `action` | string | Sí | Acción concreta ejecutada por el playbook |
| `status` | string | No (por defecto `pending`) | Estado de la respuesta |
| `triggered_by` | string | No (por defecto `automatic`) | Origen de la ejecución |
| `executed_at` | string ISO 8601 | Sí | Fecha y hora de inicio de la ejecución |
| `finished_at` | string ISO 8601 / null | No | Fecha y hora de finalización de la ejecución |
| `message` | string / null | No | Mensaje legible sobre el resultado |
| `error` | string / null | No | Error asociado si la acción ha fallado |
| `details` | object | No (por defecto `{}`) | Datos específicos de la acción |

`playbook` y `action` son texto libre: el modelo registra cualquier acción sin depender de cómo
la implemente el playbook.

## Estados previstos

- `pending`: la respuesta está registrada pero todavía no se ha ejecutado
- `running`: la acción se está ejecutando
- `success`: la acción ha terminado correctamente
- `failed`: la acción ha terminado con error (ver `error`)
- `skipped`: la acción no se ha ejecutado

Estos estados son un catálogo **distinto** de los estados del incidente (`open`, `in_progress`,
`contained`, `resolved`). Registrar una respuesta no modifica el estado del incidente.

## Orígenes previstos

- `automatic`: lanzada por el SOAR tras la decisión de automatización
- `manual`: lanzada por un analista

## Playbooks y acciones previstos

| Playbook | Acción | Sprint | Ejecuta |
| --- | --- | --- | --- |
| `brute_force` | `notify` | Sprint 2 | Módulo 6, envía el incidente al grupo 7 |
| `brute_force` | `block_ip` | Sprint 3 | Equipo 1 (módulo de identidad) |
| `brute_force` | `disable_account` | Sprint 3 | Equipo 1 (módulo de identidad) |

## Relación con Incident

Un incidente puede tener varias respuestas ejecutadas (relación 1:N), una por cada acción del
playbook o por cada nuevo intento. La relación se establece mediante `incident_id`, que
corresponde al `incident_id` del modelo `Incident` (ver `incidents.md`).
