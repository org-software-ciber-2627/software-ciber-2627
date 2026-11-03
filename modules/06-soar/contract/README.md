# Contrato de API

## `GET /health`

Devuelve `200`:

```json
{"status":"ok","module":"06-soar"}
```

## `GET /incidents`

Devuelve `200` con una lista de incidentes registrados. Cada elemento contiene
`id`, `alert_key`, `alert` y `first_seen`.

## `POST /poll`

Consulta `GET /alerts` en `SIEM_URL`. Acepta tanto una lista de alertas como
`{"alerts":[...]}`. Devuelve `200`:

```json
{"received":2,"created":1,"ignored":1}
```

Una alerta repetida se ignora y se registra en los logs; no incrementa
`created`. Si el SIEM no está disponible devuelve `502`.
