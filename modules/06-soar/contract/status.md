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
- un motivo de resolución (`resolution_reason`) al cerrar el incidente.

HU6 no expone endpoints HTTP. Este contrato describe únicamente los modelos y
las reglas del ciclo de estado.
