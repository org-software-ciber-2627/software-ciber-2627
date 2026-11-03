# Contrato de detección de automatización — HU13

## Objetivo

Determinar si un incidente registrado por el SOAR puede ser tratado automáticamente y, en caso afirmativo, indicar qué playbook corresponde.

HU13 únicamente toma la decisión de automatización. La ejecución real del playbook pertenece a HU14.

## Entrada

La detección recibe una instancia del modelo `Incident`.

Para Sprint 2 se utilizan estos campos:

- `event_type`
- `source_ip`

HU13 no modifica el incidente recibido.

## Salida

La decisión tendrá:

- `automatable`: indica si el incidente puede automatizarse.
- `playbook`: identificador del playbook aplicable o `null`.
- `reason`: explicación de la decisión.

Ejemplo automatizable:

{
  "automatable": true,
  "playbook": "brute_force",
  "reason": "Incidente compatible con el playbook de fuerza bruta"
}

Ejemplo no automatizable:

{
  "automatable": false,
  "playbook": null,
  "reason": "No existe un playbook automático compatible"
}

## Reglas Sprint 2

| event_type | Requisito adicional | Automatizable | Playbook |
|---|---|---|---|
| `fuerza_bruta` | `source_ip` presente | Sí | `brute_force` |
| `fuerza_bruta` | `source_ip` ausente | No | — |
| cualquier otro tipo | — | No | — |

## Límites

HU13 sí:
- decide si el incidente es automatizable;
- determina el playbook aplicable;
- explica el motivo.

HU13 no:
- ejecuta el playbook;
- bloquea IPs;
- llama a otros grupos;
- modifica el estado del incidente;
- persiste respuestas.

La ejecución pertenece a HU14 y el registro de la respuesta a HU15.
