# Ciclo de estado de incidentes (HU6)

## Estados

Un incidente puede estar en uno de estos estados:

- `open`: incidente abierto.
- `in_progress`: investigación o respuesta en curso.
- `contained`: la amenaza está contenida.
- `closed`: incidente cerrado.

## Transiciones permitidas

| Estado actual | Estados destino permitidos |
|---|---|
| `open` | `in_progress`, `closed` |
| `in_progress` | `contained`, `closed` |
| `contained` | `in_progress`, `closed` |
| `closed` | Ninguno |

`closed` es un estado final: no se permiten transiciones posteriores.

## Registro de cambios

Cada cambio de estado debe incluir:

- el identificador del incidente;
- el estado anterior y el nuevo estado;
- una justificación, siempre obligatoria;
- `changed_at`, una marca de tiempo con zona horaria UTC;
- un motivo de resolución (`resolution_reason`) al cerrar el incidente;
- `changed_by` (HU7), quién hace el cambio.

## Quién hace el cambio (`changed_by`, HU7)

| Origen del cambio | `changed_by` |
|---|---|
| `POST /incidents/{incident_id}/status` con autenticación activa | Username del token; no se necesita en el cuerpo |
| `POST /incidents/{incident_id}/status` al cerrar sin autenticación | **Obligatorio en el cuerpo** |
| `POST /incidents/{incident_id}/status` con otro estado y sin autenticación | Opcional; si no viene, `null` |
| Paso automático a `in_progress` tras una respuesta con éxito | `soar-automation` |
| Paso automático a `contained` tras `block_ip` con éxito (HU19.3) | `soar-automation` |

- Se quitan los espacios al principio y al final. Una cadena vacía o solo con espacios se trata como si no viniera.
- Máximo 100 caracteres.
- Con autenticación activa, `changed_by` es el `username` del token validado mediante
  `GET /auth/validate` del Módulo 1 (Identidad); el `changed_by` del cuerpo se ignora sin error.
- Sin `AUTH_URL` (desarrollo y tests), se toma del cuerpo JSON como antes.
- Se guarda dentro del registro de cada cambio (`change_json`) en la tabla `status_history`. Los
  cambios registrados antes de HU7 no tienen ese dato y se leen con `changed_by = null`.

## Cambio de estado por HTTP

`POST /incidents/{incident_id}/status`

Con un token válido, `changed_by` en el cuerpo es opcional:

```json
{
  "status": "closed",
  "justification": "Revisado por el analista",
  "resolution_reason": "IP bloqueada en el cortafuegos"
}
```

- `200`: el incidente actualizado, con el mismo formato que el modelo `Incident`, más `changed_by`.
  Al cerrar, `resolved_at` se rellena.
- `400` `{"error": "..."}`, sin cambiar el estado, si:
  - el cuerpo no es JSON o falta `status`;
  - sin autenticación, `changed_by` no es texto: `changed_by debe ser texto`;
  - el `changed_by` efectivo (username del token o valor del cuerpo sin autenticación) tiene más de 100 caracteres:
    `changed_by no puede superar 100 caracteres`;
  - sin autenticación, se cierra sin `changed_by`: `changed_by es obligatorio para cerrar un incidente`;
  - HU6 rechaza el cambio (transición no permitida, justificación vacía, cierre sin `resolution_reason`
    o incidente ya cerrado).
- `404` `{"error": "incident_not_found"}` si el incidente no existe. Tiene prioridad sobre los errores de `changed_by`.
- `401`, `403` o `503` por errores de autenticación; ver [Autenticación (HU20)](README.md#autenticación-hu20).

Ejemplo de respuesta `200` al cerrar (se omiten algunos campos del incidente):

```json
{
  "incident_id": "INC-4F9A2C",
  "status": "closed",
  "resolved_at": "2026-11-20T10:15:00.123456+00:00",
  "changed_by": "analista.fer"
}
```

## Historial por HTTP (HU7)

`GET /incidents/{incident_id}/history`

Devuelve `200` con la lista de cambios de estado del incidente, **del más antiguo al más reciente**
(ordenados por `changed_at`; si dos cambios tienen la misma hora, en el orden en que se registraron).

| Campo | Tipo | Admite `null` | Significado |
|---|---|---|---|
| `from_status` | string | No | Estado anterior |
| `to_status` | string | No | Estado nuevo |
| `justification` | string | No | Justificación del cambio |
| `resolution_reason` | string | Sí | Motivo de resolución; solo al cerrar |
| `changed_by` | string | Sí | Quién hizo el cambio; `soar-automation` para los automáticos y `null` en los cambios anteriores a HU7 |
| `changed_at` | string ISO 8601 en UTC, terminado en `Z` | No | Marca de tiempo del cambio |

- Incidente sin cambios de estado → `200` con `[]`.
- Incidente inexistente → `404` `{"error": "incident_not_found"}`.

Ejemplo de un incidente de fuerza bruta contenido automáticamente (HU19.3) que después cierra un analista:

```json
[
  {
    "from_status": "open",
    "to_status": "in_progress",
    "justification": "Respuesta automática ejecutada: block_ip",
    "resolution_reason": null,
    "changed_by": "soar-automation",
    "changed_at": "2026-11-20T10:00:00.120000Z"
  },
  {
    "from_status": "in_progress",
    "to_status": "contained",
    "justification": "IP 192.168.1.50 bloqueada en la lista negra",
    "resolution_reason": null,
    "changed_by": "soar-automation",
    "changed_at": "2026-11-20T10:00:00.121000Z"
  },
  {
    "from_status": "contained",
    "to_status": "closed",
    "justification": "Revisado por el analista",
    "resolution_reason": "IP bloqueada en el cortafuegos",
    "changed_by": "analista.fer",
    "changed_at": "2026-11-20T10:15:00.123456Z"
  }
]
```

## Uso para el MTTR (HU16)

- `resolved_at` se rellena **una sola vez**, al pasar a `closed`, con el `changed_at` de ese cambio.
  Ya no cambia, porque `closed` es un estado final: cualquier cambio posterior devuelve `400` y no se registra.
- Está en UTC (ISO 8601 con zona), igual que `created_at`, así que se pueden restar directamente.
- **MTTR de un incidente = `resolved_at` − `created_at`.** Los incidentes no cerrados (`resolved_at = null`)
  no entran en el cálculo.
- Aviso de formato: `resolved_at` y `created_at` (en `GET /incidents`) van con `+00:00`, y `changed_at`
  (en `GET /incidents/{incident_id}/history`) va con `Z`. Hay que comparar **fechas**, no texto.
- La fórmula definitiva del MTTR la fija HU16. Si HU16 decide medirlo hasta la contención en lugar del
  cierre, la fecha está en el `changed_at` del cambio a `contained` de `GET /incidents/{incident_id}/history`.
