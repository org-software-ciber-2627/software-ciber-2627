# Contrato de API · Dashboard (consumidor)

El Dashboard no expone ninguna API que otros módulos consuman: es el último eslabón de la cadena. Este documento recoge cada endpoint que consume, con método, campos requeridos y ejemplo.

Cada endpoint indica su estado:
- **Publicado**: el equipo proveedor lo ha publicado en `main`. Los campos son los de su contrato.
- **Propuesta**: lo fija el Dashboard a partir de sus historias de usuario porque el proveedor aún no ha publicado su contrato. El proveedor debe confirmarlo o corregirlo en el PR que añade el suyo. Hasta entonces es la referencia para el mock del Dashboard.

## Expone

Nada.

## Consume

### Identidad (`equipo-01-identidad`)

Contrato de origen: `modules/01-identidad/contract/openapi.yaml` y `shared/auth-contract.md` (v1.0.2). Si este documento y el suyo difieren, manda el de Identidad. Servicio en `http://localhost:8001`.

**`POST /auth/login`** (publicado)
- Campos de petición: `username` (string, requerido), `password` (string, requerido).
- Respuesta 200: `token` (JWT HS256, caduca a los 30 minutos) y `user` (`id` entero, `username`, `email`, `role`).
- Respuesta 400: falta usuario o contraseña. Respuesta 401: credenciales incorrectas (mensaje genérico, sin revelar si el usuario existe). Cuerpo de error: `{"error": "<mensaje>"}`.

```json
{ "username": "analista1", "password": "••••••••" }
```
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": { "id": 1, "username": "analista1", "email": "analista1@ciberurjc.local", "role": "analista" }
}
```

**`GET /auth/validate`** (publicado)
- Cabecera: `Authorization: Bearer <token>`.
- Respuesta 200: `valid` (`true`), `user_id` (entero), `username` (string), `role` (`admin` | `analista` | `servicio`).
- Respuesta 401: token inválido, expirado o ausente, con `{"valid": false, "error": "<mensaje>"}`.

```json
{ "valid": true, "user_id": 1, "username": "analista1", "role": "analista" }
```

**Pendiente de Identidad** (respuesta del equipo del 22/10, aún no está en `main`):
- CORS para el origen `http://localhost:8007`. En `main` solo está habilitado en `/auth/login` y `/auth/register`; en `/auth/validate` todavía no, y el navegador bloquea la llamada hasta que lo suban.
- Límite de intentos de login: tras 5 fallos seguidos, `/auth/login` devolverá `429`. Todavía no está en `main` ni en su contrato.
- `POST /auth/logout` existe en su código pero no está en su contrato: no lo usamos hasta que lo publiquen.

### SIEM (`equipo-05-siem`)

Contrato de origen: `modules/05-siem/contract/openapi.json` (versión `0.2.0-sprint1-review`, borrador pendiente de ratificación entre equipos). Servicio en `http://localhost:8005`.

**`GET /alerts`** (publicado como borrador)
- Respuesta 200: `{"alerts": [...]}`. Lista vacía: `{"alerts": []}`.
- Sin filtros, paginación ni orden garantizado: el Dashboard ordena y filtra en el navegador.
- Campos de cada alerta, todos requeridos: `alert_id` (string), `event_id` (string), `timestamp` (UTC, ISO 8601), `source` (`ids` | `honeypot` | `scanner`), `event_type` (string), `severity` (`low` | `medium` | `high` | `critical`), `title` (string), `description` (string), `source_ip` (IPv4 o `null`), `target_ip` (IPv4 o `null`) y `details` (objeto con datos propios de cada módulo).
- El Dashboard usa `severity`, `title`, `source` y `timestamp` en el listado.
- Autenticación: su contrato la deja pendiente y hoy el SIEM no comprueba ningún token. El Dashboard envía `Authorization: Bearer <token>` igualmente.
- CORS: el SIEM no lo tiene configurado. Pendiente de que Equipo 5 responda.

```json
{
  "alerts": [
    {
      "alert_id": "SIEM-ALERT-EJEMPLO-001",
      "event_id": "IDS-EJEMPLO-001",
      "timestamp": "2026-09-22T18:30:15Z",
      "source": "ids",
      "event_type": "port_scan",
      "severity": "medium",
      "title": "Posible escaneo de puertos",
      "description": "Una IP ha contactado con 20 puertos del mismo destino en 60 segundos.",
      "source_ip": "192.168.1.50",
      "target_ip": "192.168.1.10",
      "details": { "rule_id": "IDS-001", "protocol": "tcp", "distinct_ports_count": 20, "window_seconds": 60 }
    }
  ]
}
```

**`GET /alerts/{id}`** (publicado como borrador)
- `{id}` es el `alert_id`.
- Respuesta 200: la alerta con los mismos campos que en el listado.
- Respuesta 404: `{"error": {"code": "ALERT_NOT_FOUND", "message": "The requested alert does not exist"}}`.
- No existe `related_events`: su contrato prohíbe añadirlo sin acuerdo. El detalle de una alerta se limita a sus campos, incluido `details`.

### SOAR (`equipo-06-soar`)

**`GET /incidents`** (propuesta)

Su `contract/README.md` sigue vacío en `main`, así que estos campos son nuestra propuesta y no están confirmados. Las fechas de detección y resolución se necesitan para calcular MTTD y MTTR.

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

Su `contract/README.md` sigue vacío en `main`. Sin contrato todavía: el Dashboard usa su mock hasta que el Escáner publique los campos de un hallazgo.

## Salud de los módulos

Todos los módulos publican `GET /health`. Respuesta esperada: **200** con `{"status":"ok"}`. El Dashboard consulta este endpoint de los 8 módulos para la vista de salud de integración.

```json
{ "status": "ok" }
```

## Mocks

Mientras una dependencia no esté disponible, el Dashboard trabaja contra su propio mock en `modules/07-dashboard/mocks/`, con datos de ejemplo fijos.

- El mock del SIEM (`siem-alerts.json`) respeta el formato publicado por el SIEM.
- Los mocks de SOAR (`GET /incidents`, puerto 5001) y Escáner (`GET /findings`, puerto 5002) son provisionales y **no coinciden** con la propuesta de arriba: devuelven `id`, `title`, `severity`, `status`, `description` y, el de SOAR, `source`; el del Escáner, `target`. Hay que alinearlos cuando esos equipos publiquen su contrato.
- La URL del SIEM es una constante en `src/SIEM-client.js`; para apuntar al servicio real se cambia ahí.
