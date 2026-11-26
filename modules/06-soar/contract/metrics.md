# HU16 — Cálculo automático de MTTD y MTTR

## Fórmulas propuestas

MTTD = created_at - alert_timestamp

- alert_timestamp: timestamp original recibido del SIEM.
- created_at: instante de creación del incidente en el SOAR.
- Solo se calculan duraciones válidas y no negativas.

MTTR = resolved_at - created_at

- Se calcula únicamente sobre incidentes con status = closed.
- resolved_at indica la fecha de cierre del incidente.
- Un incidente en estado contained no se considera cerrado.

## Unidades y tratamiento de fechas

- Todas las duraciones se expresan en segundos.
- Las fechas deben incluir zona horaria y se normalizan a UTC.
- Un valor desconocido se representa como null, no como 0.
- Una duración real de 0 segundos sí es válida.
- Las medias excluyen únicamente los valores desconocidos o inválidos.

## Resultados globales para HU18

- mttd_seconds: media de los MTTD válidos.
- mttr_seconds: media de los MTTR válidos de incidentes cerrados.
- total_incidents: número total de incidentes.
- closed_incidents: número total de incidentes cerrados.

Ejemplo:

{
  "mttd_seconds": 12.4,
  "mttr_seconds": 85.7,
  "total_incidents": 10,
  "closed_incidents": 6
}

## Casos especiales

Sin incidentes:
- Ambas medias null.
- Ambos contadores 0.

Sin incidentes cerrados:
- mttr_seconds es null.

Fecha ausente, inválida, sin zona horaria o duración negativa:
- La métrica correspondiente es null.

## Pendiente de acuerdo con Grupo 5

Confirmar que timestamp corresponde a la detección de la alerta
y que la diferencia hasta created_at es la métrica que se quiere
denominar MTTD. Hasta esa confirmación, la fórmula es provisional.

## Responsabilidades

HU16: cálculo de métricas.
HU18: exposición HTTP mediante GET /metrics.
HU17: visualización e integración con Grupo 7.

## Exposición HTTP (HU18)

`GET /metrics` no requiere parámetros y devuelve un objeto con exactamente estos cuatro campos:

| Nombre | Tipo | Admite `null` | Significado | Unidad |
|---|---|---|---|---|
| `mttd_seconds` | número | Sí | Media de los MTTD válidos | segundos |
| `mttr_seconds` | número | Sí | Media de los MTTR válidos de incidentes cerrados | segundos |
| `total_incidents` | entero | No | Número total de incidentes | incidentes |
| `closed_incidents` | entero | No | Número de incidentes cerrados | incidentes |

### Códigos de respuesta

- `200` siempre que las métricas se puedan calcular. Sin datos, las medias son `null` y los contadores `0`.
- `500` `{"error":"internal_error"}` si se produce un error no previsto.

### Ejemplos

Con datos:

```json
{
  "mttd_seconds": 12.4,
  "mttr_seconds": 85.7,
  "total_incidents": 10,
  "closed_incidents": 6
}
```

Sin incidentes:

```json
{"mttd_seconds": null, "mttr_seconds": null, "total_incidents": 0, "closed_incidents": 0}
```

El formato queda congelado desde el 26/11; cualquier cambio va al registro de cambios del SoS.

Con autenticación activa (HU20), exige `Authorization: Bearer <token>`; si `AUTH_URL` no está
configurada, se aplica el modo abierto de desarrollo y tests descrito en
[`README.md`](README.md#autenticación-hu20).
