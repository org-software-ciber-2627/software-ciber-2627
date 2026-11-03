# Contrato de incidentes del SOAR

Este documento define la estructura de un incidente utilizada por el módulo 6 (SOAR ligero).

## Modelo Incident

```json
{
  "incident_id": "INC-001",
  "alert_id": "SIEM-ALERT-EJEMPLO-002",
  "event_type": "fuerza_bruta",
  "severity": "medium",
  "source_ip": "192.168.1.50",
  "status": "open",
  "created_at": "2026-09-22T18:30:20Z",
  "resolved_at": null
}
```

## Campos

| Campo | Tipo | Obligatorio | Descripción |
| --- | --- | --- | --- |
| `incident_id` | string | Sí | Identificador único del incidente |
| `alert_id` | string | Sí | Identificador de la alerta del SIEM que originó el incidente |
| `event_type` | string | Sí | Tipo de evento o amenaza |
| `severity` | string | Sí | Severidad del incidente |
| `source_ip` | string / null | No | IP de origen relacionada con el incidente |
| `status` | string | Sí | Estado actual del incidente |
| `created_at` | string ISO 8601 | Sí | Fecha y hora de creación del incidente |
| `resolved_at` | string ISO 8601 / null | No | Fecha y hora de resolución del incidente |

## Estados previstos

- `open`
- `in_progress`
- `contained`
- `resolved`

## Severidades previstas

- `low`
- `medium`
- `high`
- `critical`
