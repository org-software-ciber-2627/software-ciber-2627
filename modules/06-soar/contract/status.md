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
| `POST /incidents/{incident_id}/status` que cierra el incidente (`status: closed`) | **Obligatorio** |
| `POST /incidents/{incident_id}/status` con cualquier otro estado | Opcional; si no viene, `null` |
| Paso automático a `in_progress` tras una respuesta con éxito | `soar-automation` |

- Se quitan los espacios al principio y al final. Una cadena vacía o solo con espacios se trata como si no viniera.
- Máximo 100 caracteres.
- Hoy se envía en el cuerpo JSON. Más adelante vendrá del token del Módulo 1 (identidad).
- Se guarda dentro del registro de cada cambio (`change_json`) en la tabla `status_history`. Los
  cambios registrados antes de HU7 no tienen ese dato y se leen con `changed_by = null`.

## Cambio de estado por HTTP

`POST /incidents/{incident_id}/status`

```json
{
  "status": "closed",
  "justification": "Revisado por el analista",
  "resolution_reason": "IP bloqueada en el cortafuegos",
  "changed_by": "analista.fer"
}
```

- `200`: el incidente actualizado, con el mismo formato que el modelo `Incident`, más `changed_by`.
  Al cerrar, `resolved_at` se rellena.
- `400` `{"error": "..."}`, sin cambiar el estado, si:
  - el cuerpo no es JSON o falta `status`;
  - `changed_by` no es texto: `changed_by debe ser texto`;
  - `changed_by` tiene más de 100 caracteres: `changed_by no puede superar 100 caracteres`;
  - se cierra sin `changed_by`: `changed_by es obligatorio para cerrar un incidente`;
  - HU6 rechaza el cambio (transición no permitida, justificación vacía, cierre sin `resolution_reason`
    o incidente ya cerrado).
- `404` `{"error": "incident_not_found"}` si el incidente no existe. Tiene prioridad sobre los errores de `changed_by`.

Ejemplo de respuesta `200` al cerrar (se omiten algunos campos del incidente):

```json
{
  "incident_id": "INC-4F9A2C",
  "status": "closed",
  "resolved_at": "2026-11-20T10:15:00.123456+00:00",
  "changed_by": "analista.fer"
}
```
