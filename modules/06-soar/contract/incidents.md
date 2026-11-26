# Contrato de incidentes del SOAR

> **Nota:** la primera sección describe el **modelo interno** `Incident` del módulo 6. La segunda
> sección fija el **contrato público congelado de `GET /incidents`** acordado con el Módulo 7
> (Dashboard) en **HU12.2 (`SB-71`)**. El resto de endpoints está en [`contract/README.md`](README.md).

Este documento define tanto la estructura interna de un incidente como el contrato de exposición HTTP utilizado por el módulo 6 (SOAR ligero).

---

## 1. Modelo interno `Incident`

```json
{
  "incident_id": "INC-001",
  "alert_id": "SIEM-ALERT-EJEMPLO-002",
  "event_type": "fuerza_bruta",
  "severity": "medium",
  "source_ip": "192.168.1.50",
  "status": "open",
  "created_at": "2026-09-22T18:30:20Z",
  "resolved_at": null,
  "priority": "medium",
  "source": "honeypot",
  "target_ip": null,
  "title": "Intento de fuerza bruta en el honeypot",
  "description": "El honeypot ha registrado un evento clasificado como fuerza bruta sobre SSH.",
  "details": {"service": "ssh", "username": "root"},
  "alert_key": "SIEM-ALERT-EJEMPLO-002"
}

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
| `resolved_at` | string ISO 8601 / null | No | Fecha y hora de cierre del incidente (se rellena al pasar a `closed`) |
| `priority` | string / null | No | Prioridad calculada por HU5 (ver `priority.md`) |
| `source` | string / null | No | Productor de la alerta: `ids`, `honeypot`, `scanner` o `pentesting` |
| `target_ip` | string / null | No | IP de destino |
| `title` | string / null | No | Resumen legible de la alerta |
| `description` | string / null | No | Explicación legible de la alerta |
| `details` | object | No (por defecto `{}`) | Datos específicos del productor |
| `alert_key` | string / null | No | Clave de idempotencia de la alerta (tabla `incidents`) |

Los campos a partir de `priority` se añadieron en el Sprint 2 y son opcionales.
El incidente se crea al normalizar la alerta del SIEM (`soar/normalization/parser.py`),
con `incident_id` `INC-XXXXXX`, `status` `open` y `created_at` en UTC.

## Estados previstos

Son los de HU6 (ver `status.md`):

- `open`
- `in_progress`
- `contained`
- `closed`

## Severidades previstas

- `low`
- `medium`
- `high`
- `critical`
