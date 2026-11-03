# Contrato de API · Dashboard (consumidor)

El Dashboard no expone ninguna API que otros módulos consuman: es el último eslabón de la cadena. Este documento recoge cada endpoint que consume, con método, campos requeridos y ejemplo.

Cada endpoint indica su estado:
- **Publicado**: el equipo proveedor lo ha publicado en `main`. Los campos son los de su contrato.
- **Borrador / deducido**: el proveedor no ha publicado su contrato en `main`, pero hay un borrador suyo en una rama o su código ya está en `main`. Los campos salen de ahí y no están confirmados por el equipo. Es la referencia para el mock del Dashboard.
- **Propuesta**: lo fija el Dashboard a partir de sus historias de usuario porque el proveedor aún no ha publicado nada. El proveedor debe confirmarlo o corregirlo en el PR que añade su contrato.

## Expone

Nada.

## Consume

### Identidad (`equipo-01-identidad`)

Contrato de origen: `modules/01-identidad/contract/openapi.yaml` y `shared/auth-contract.md` (v1.2.0). Si este documento y el suyo difieren, manda el de Identidad. Servicio en `http://localhost:8001`.

**`POST /auth/login`** (publicado)
- Campos de petición: `username` (string, requerido), `password` (string, requerido).
- Respuesta 200: `token` (JWT HS256, caduca a los 30 minutos) y `user` (`id` entero, `username`, `email`, `role`).
- Respuesta 400: falta usuario o contraseña. Respuesta 401: credenciales incorrectas (mensaje genérico, sin revelar si el usuario existe). Respuesta 429: demasiados intentos fallidos; bloqueo temporal por combinación de usuario e IP, con la cabecera `Retry-After` (segundos restantes). Cuerpo de error: `{"error": "<mensaje>"}`.

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

**`POST /auth/logout`** (publicado, v1.2.0)
- Cabecera: `Authorization: Bearer <token>`. Sin cuerpo.
- Respuesta 200: `{"message": "Token revocado"}`. A partir de ahí ese token deja de valer: `GET /auth/validate` responde 401 con él.
- Respuesta 401: token inválido, expirado, revocado o ausente (también si ya se había cerrado la sesión con él).

**CORS** (publicado el 27/10): solo se permite el origen `http://localhost:8007`, y solo en `POST /auth/login` y `POST /auth/register`. `GET /auth/validate` y `POST /auth/logout` no están en esa lista, así que una llamada directa desde el navegador a esos dos endpoints se bloquea. Hay que pedir a Equipo 1 que los añada o llamarlos a través de un proxy del nginx del Dashboard (como se hace con el SIEM).

**No lo consume el Dashboard en el Sprint 2:** `GET /audit` (solo `admin`). Su contrato lo documenta, pero el código de Identidad expone `GET /logs`; la diferencia ya se la hemos comunicado a Equipo 1.

### SIEM (`equipo-05-siem`)

Contrato de origen: `modules/05-siem/contract/openapi.json` (versión `0.2.0-sprint1-review`, borrador pendiente de ratificación entre equipos). Servicio en `http://localhost:8005`.

**`GET /alerts`** (publicado como borrador)
- Respuesta 200: `{"alerts": [...]}`. Lista vacía: `{"alerts": []}`.
- Sin filtros, paginación ni orden garantizado: el Dashboard ordena y filtra en el navegador.
- Campos de cada alerta, todos requeridos: `alert_id` (string), `event_id` (string), `timestamp` (UTC, ISO 8601), `source` (`ids` | `honeypot` | `scanner`), `event_type` (string), `severity` (`low` | `medium` | `high` | `critical`), `title` (string), `description` (string), `source_ip` (IPv4 o `null`), `target_ip` (IPv4 o `null`) y `details` (objeto con datos propios de cada módulo).
- El Dashboard usa `severity`, `title`, `source` y `timestamp` en el listado.
- Autenticación: su contrato la deja pendiente y hoy el SIEM no comprueba ningún token. El Dashboard envía `Authorization: Bearer <token>` igualmente.
- CORS: el SIEM no lo tiene configurado (comprobado el 27/10: no devuelve `Access-Control-Allow-Origin`). El Dashboard lo resuelve con un proxy en su nginx, así que no necesita nada de Equipo 5.

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

**`GET /incidents`** (borrador)

Lo acordado con Equipo 6 en el Scrum de Scrums del 27/10 (minuta en Miro): `GET /incidents` devuelve una lista directa, `[]` si no hay incidentes, y un campo opcional `applied_playbook` (id del playbook o `null`). Usamos su JSON como mock.

Lo publicado por ellos todavía no coincide con eso, y por eso el formato sigue siendo un borrador:
- Su `contract/README.md` en `main` describe una respuesta con `id`, `alert_key`, `alert` y `first_seen`, y es lo que hace el código de `main`.
- Su rama `equipo-06-soar/integracion-sprint2` (sin PR) tiene `contract/incidents.md` con el modelo de abajo (`incident_id`, `alert_id`…), pero su `src/app.py` sigue devolviendo la forma anterior (`id`, `alert_key`, `alert`, `first_seen`). Tampoco aparece `applied_playbook` en ninguno de los dos.
- Hasta que publiquen un único formato, el Dashboard sigue el modelo de `incidents.md` más `applied_playbook`.

- Respuesta 200: lista directa de incidentes. Sin incidentes: `[]`.
- Campos de cada incidente: `incident_id` (string, requerido), `alert_id` (`alert_id` de la alerta del SIEM que lo originó, requerido), `event_type` (string, requerido), `severity` (`low` | `medium` | `high` | `critical`, requerido), `source_ip` (string o `null`), `status` (`open` | `in_progress` | `contained` | `resolved`, requerido), `created_at` (ISO 8601, requerido), `resolved_at` (ISO 8601 o `null`) y `applied_playbook` (string o `null`, opcional: si falta se trata como `null`).
- `applied_playbook` es lo que pide la historia del listado de incidentes (DASHG7-26). Hoy el único playbook previsto en su contrato de automatización es `brute_force`, para `fuerza_bruta` con `source_ip`.
- MTTR: `resolved_at` − `created_at`. MTTD: `created_at` − `timestamp` de la alerta (se busca con `alert_id` en el SIEM), suponiendo que `created_at` es cuando se crea el incidente.

```json
[
  {
    "incident_id": "INC-001",
    "alert_id": "SIEM-ALERT-EJEMPLO-002",
    "event_type": "fuerza_bruta",
    "severity": "medium",
    "source_ip": "192.168.1.50",
    "status": "open",
    "created_at": "2026-09-22T18:30:20Z",
    "resolved_at": null,
    "applied_playbook": "brute_force"
  }
]
```

### Escáner (`equipo-04-escaner`)

Su `contract/README.md` sigue vacío en `main`. Lo que sigue se **deduce de su código** en `main` (`main.py`, `jobs.py`, `parser.py`) y no está confirmado por el equipo. Servicio en `http://localhost:8004`.

**`GET /events`** (deducido)
- Respuesta 200: lista de escaneos, sin sus eventos: `scan_id` (UUID), `target`, `profile` (`vuln` | `web` | `quick`) y `status` (`running` | `completed` | `failed`).
- No hay fecha del escaneo: el más reciente es el último de la lista.

**`GET /scan/{scan_id}`** (deducido)
- Respuesta 200: los mismos campos que en la lista y `events`, la lista de hallazgos (vacía mientras corre).
- Respuesta 404: `{"error": "scan no encontrado"}`.
- Cada hallazgo tiene `event_id`, `timestamp`, `source`, `event_type`, `severity` (`low` | `medium` | `high` | `critical`, según el CVSS), `title` (el CVE o el script), `description`, `target` (`ip`, `port`, `protocol`, `service`) y `details` (`scan_id`, `tool`, `profile`, `script_id`, `evidence`, `cve`, `cvss`; los dos últimos pueden ser `null`).

```json
{
  "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01",
  "target": "192.168.56.10",
  "profile": "vuln",
  "status": "completed",
  "events": [
    {
      "event_id": "0c2d8a4e-1b3f-4a6c-8d9e-aa11bb22cc01",
      "timestamp": "2026-10-20T10:15:00Z",
      "source": "vulnerability_scanner",
      "event_type": "vulnerability_detected",
      "severity": "high",
      "title": "CVE-2014-0160",
      "description": "VULNERABLE:",
      "target": { "ip": "192.168.56.10", "port": 443, "protocol": "tcp", "service": "https" },
      "details": { "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01", "tool": "nmap", "profile": "vuln", "script_id": "ssl-heartbleed", "evidence": "VULNERABLE: ...", "cve": "CVE-2014-0160", "cvss": 7.5 }
    }
  ]
}
```

Limitaciones que se ven en el código y habría que confirmar con Equipo 4:
- Los escaneos se guardan en memoria y se pierden al reiniciar el contenedor.
- `source` es `vulnerability_scanner` y `target` va en la raíz, y el schema de eventos del SIEM exige `scanner` y no admite campos extra. Es un asunto entre Equipo 4 y Equipo 5, no del Dashboard.

## Salud de los módulos

Todos los módulos publican `GET /health`. Respuesta esperada: **200** con `{"status":"ok"}`. El Dashboard consulta este endpoint de los 8 módulos para la vista de salud de integración.

```json
{ "status": "ok" }
```

## Mocks

Mientras una dependencia no esté disponible, el Dashboard trabaja contra su propio mock en `modules/07-dashboard/mocks/`, con datos de ejemplo fijos.

- El mock del SIEM (`siem-alerts.json`) respeta el formato publicado por el SIEM.
- El mock de SOAR (`GET /incidents`, puerto 5001) sigue el borrador de Equipo 6 con `applied_playbook` y el del Escáner (`GET /events` y `GET /scan/{id}`, puerto 5002) sigue lo que se deduce de su código. Ninguno está confirmado por su equipo: hay que revisarlos cuando publiquen su contrato.
- La URL del SIEM es una constante en `src/SIEM-client.js`. Apunta a `/api/siem/alerts`, que el nginx del Dashboard (`default.conf`) reenvía al SIEM real; para usar el mock se cambia por `../mocks/siem-alerts.json`.
