# Contrato de API · Dashboard (consumidor)

El Dashboard no expone ninguna API que otros módulos consuman: es el último eslabón de la cadena. Este documento recoge cada endpoint que consume, con método, campos requeridos y ejemplo.

Los campos marcados como **propuesta** los fija el Dashboard a partir de sus historias de usuario. El equipo proveedor debe confirmarlos o corregirlos (en el PR que añade su contrato). Hasta que lo haga, son la referencia para el mock del Dashboard.

## Expone

Nada.

## Consume

### Identidad (`equipo-01-identidad`)

**`POST /auth/login`** (propuesta)
- Campos de petición: `usuario` (string, requerido), `password` (string, requerido).
- Respuesta 200: `token` (JWT, string, requerido).
- Respuesta 401: mensaje genérico, sin revelar si el usuario existe.

```json
{ "usuario": "analista1", "password": "••••••••" }
```
```json
{ "token": "eyJhbGciOiJIUzI1NiJ9.eyJyb2wiOiJhbmFsaXN0YSJ9.sig" }
```

**`GET /auth/validate`** (propuesta)
- Cabecera: `Authorization: Bearer <token>`.
- Respuesta 200: `usuario` (string), `rol` (`admin` | `analista` | `servicio`).
- Respuesta 401: token caducado o rechazado.

```json
{ "usuario": "analista1", "rol": "analista" }
```

### SIEM (`equipo-05-siem`)

**`GET /alerts`** (propuesta)
- Respuesta 200: lista de alertas con `id` (string, requerido), `titulo` (string, requerido), `severidad` (`alta` | `media` | `baja`, requerido), `modulo_origen` (string, requerido), `fecha` (ISO 8601, requerido).

```json
[
  {
    "id": "alr-0042",
    "titulo": "Múltiples intentos de login fallidos",
    "severidad": "alta",
    "modulo_origen": "ids",
    "fecha": "2026-10-06T14:32:10Z"
  }
]
```

**`GET /alerts/{id}`** (propuesta)
- Respuesta 200: los campos de la alerta más `eventos` (lista de identificadores de evento que la originaron).
- Respuesta 404: `{"error": "alerta no encontrada"}`.

### SOAR (`equipo-06-soar`)

**`GET /incidents`** (propuesta)
- Respuesta 200: lista de incidentes con `id` (string, requerido), `alerta_origen` (id de alerta, requerido), `estado` (`abierto` | `resuelto`, requerido), `fecha_creacion` (ISO 8601, requerido), `playbook` (string, opcional).

```json
[
  {
    "id": "inc-0007",
    "alerta_origen": "alr-0042",
    "estado": "abierto",
    "fecha_creacion": "2026-10-06T14:40:00Z",
    "playbook": "bloqueo-ip"
  }
]
```

### Escáner (`equipo-04-escaner`)

Histórico de hallazgos, si el Escáner decide exponerlo. Sin contrato todavía: el Dashboard usa su mock hasta que el Escáner lo publique.

## Salud de los módulos

Todos los módulos publican `GET /health`. Respuesta esperada: **200** con `{"status":"ok"}`. El Dashboard consulta este endpoint de los 8 módulos para la vista de salud de integración.

```json
{ "status": "ok" }
```

## Mocks

Mientras una dependencia no esté disponible, el Dashboard trabaja contra su propio mock en `modules/07-dashboard/mocks/`, con datos de ejemplo fijos que respetan los contratos de esta página. Las variables de entorno (`SIEM_URL`, `SOAR_URL`, etc., ver `.env.example`) permiten apuntar al mock o al servicio real sin tocar código.
