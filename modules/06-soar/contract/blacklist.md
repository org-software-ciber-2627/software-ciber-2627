# Lista negra simulada de IPs (HU19)

La acción `block_ip` del playbook de fuerza bruta (HU19.2) mete la IP atacante en una **lista negra
simulada** dentro del SOAR. No se bloquea la IP en ningún sistema real: el bloqueo real en Identidad
queda en el backlog futuro (acordado con el grupo 1 el 24/11).

Desde HU19.3 la lista negra está **conectada al flujo de sondeo** (`POST /poll` y el sondeo periódico):
cada alerta de fuerza bruta nueva ejecuta `block_ip` sobre su `source_ip`, y si la IP queda en la lista
el incidente pasa a `contained` (ver `status.md`). Los efectos en el flujo están en `playbook.md`.

## Modelo `BlacklistEntry`

| Campo | Tipo | Significado |
|---|---|---|
| `ip` | string | IP bloqueada (IPv4 o IPv6), normalizada; por ejemplo, `2001:0db8::0001` se guarda como `2001:db8::1` y `::ffff:1.2.3.4` como `1.2.3.4` |
| `incident_id` | string | Incidente que provocó el bloqueo |
| `added_at` | string ISO 8601 en UTC | Fecha y hora del bloqueo. Se rechazan las fechas sin zona horaria |
| `reason` | string | Motivo del bloqueo |

Se guarda en la tabla `ip_blacklist` del SQLite del módulo (el mismo `DATABASE_PATH`), con la IP
como clave primaria: **una IP solo puede aparecer una vez**.

## Resultado de bloquear una IP

`BlacklistService.block(ip, incident_id, reason)` devuelve un `BlockResult` con `outcome`, `ip`,
`entry` y `message`. `outcome` toma uno de estos valores:

| `outcome` | Cuándo | Qué se guarda | `entry` |
|---|---|---|---|
| `blocked` | IP válida, no excluida y que no estaba en la lista | Una entrada nueva | La entrada nueva |
| `already_blocked` | La IP ya estaba en la lista | Nada: **no se duplica ni se cambia** la entrada original | La entrada original |
| `invalid_ip` | IP vacía, `null`, que no es texto o que no es una IPv4/IPv6 válida (las redes como `10.0.0.0/8` tampoco valen) | Nada | `null` |
| `excluded` | IP que nunca debe bloquearse (ver la regla siguiente) | Nada | `null` |

HU19.2 convertirá estos valores en el `status` de la respuesta ejecutada (`success`, `failed` o `skipped`).

## Regla de exclusiones

Nunca se bloquean:

- loopback: `127.0.0.0/8` y `::1`;
- la IP no especificada: `0.0.0.0` (y `::`);
- las redes de la variable de entorno opcional `BLACKLIST_EXCLUDED_NETWORKS`, una lista separada por
  comas, por ejemplo la subred del `docker-compose.yml` global:

  ```
  BLACKLIST_EXCLUDED_NETWORKS=172.28.0.0/16,fd00::/8
  ```

  Una red mal escrita se ignora con un `WARNING` en el log, sin tumbar el servicio. Si la variable no
  está definida, solo se aplican las exclusiones fijas.

Las IPs privadas (`192.168.x.x`, `10.x.x.x`, `172.16.0.0/12`) **sí** se pueden bloquear, porque las
alertas de la demo llegan con IPs así. Si una subred privada no debe bloquearse, se añade a
`BLACKLIST_EXCLUDED_NETWORKS`.

## `GET /blacklist` (BORRADOR)

> **Borrador.** El endpoint se implementa en HU19.4 y el formato se congela el **26/11**. Hasta
> entonces puede cambiar.

Devuelve `200` con la lista de IPs bloqueadas, de la más antigua a la más reciente (por `added_at`),
o `[]` si la lista está vacía.

```json
[
  {
    "ip": "192.168.1.50",
    "incident_id": "INC-F98CDC",
    "added_at": "2026-11-24T10:00:00.123456Z",
    "reason": "Fuerza bruta SSH detectada por el honeypot"
  }
]
```
