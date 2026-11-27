# Contrato de priorización — HU5

## Objetivo

Asignar a cada incidente una prioridad a partir de su severidad y su tipo de evento.

## Entrada y salida

- `prioritize(incident: Incident) -> Incident`: devuelve una copia del incidente con `priority` rellenado.
- `calculate_priority(incident_data: dict) -> PriorityLevel` y `prioritize_incident(incident: dict) -> dict`
  se mantienen para trabajar con diccionarios.

La priorización no modifica el incidente recibido.

## Niveles

- `low`
- `medium`
- `high`
- `critical`

## Reglas (en orden)

| Condición | Prioridad |
|---|---|
| `event_type` es `ransomware_detected` o `data_exfiltration`, o `severity` es `critical` | `critical` |
| `severity` es `low`, `medium` o `high` | la misma que la severidad |
| `severity` ausente o desconocida | `low` |

`severity` y `event_type` se comparan en minúsculas.
