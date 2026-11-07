# Contrato de autenticación (Identidad y secretos)

El equipo `equipo-01-identidad` publica aquí, en el Sprint 1, el contrato de los endpoints que expone.
La fuente de verdad es [`modules/01-identidad/contract/openapi.yaml`](../modules/01-identidad/contract/openapi.yaml)
(versión 1.1.0); si este resumen y el YAML difieren, manda el YAML. Los cambios se hacen por Pull Request
y se avisan por Teams a los equipos que usen el endpoint.

Servicio en local con `docker compose up`: `http://localhost:8001` (puerto interno `80` dentro del compose).

**Historial.** 1.1.0: se añade `GET /audit` (registro de auditoría, solo `admin`). Es un cambio compatible: no modifica los endpoints existentes.

## Endpoints

### `POST /auth/login`
- **Request:**
  ```json
  { "username": "usuario.ejemplo", "password": "contraseña-de-ejemplo" }
  ```
- **Response `200`:**
  ```json
  { "token": "<jwt>", "user": { "id": 1, "username": "usuario.ejemplo", "email": "usuario.ejemplo@ciberurjc.local", "role": "analista" } }
  ```
- **Errores:** `400` falta usuario o contraseña · `401` credenciales incorrectas · `500` error inesperado. Cuerpo: `{ "error": "<mensaje>" }`.
- Cada intento de login queda en el registro de auditoría (ver `GET /audit`).

### `GET /auth/validate`
- **Request:** cabecera `Authorization: Bearer <jwt>`.
- **Response `200`:**
  ```json
  { "valid": true, "user_id": 1, "username": "usuario.ejemplo", "role": "analista" }
  ```
- **Errores:** `401` token inválido, expirado o ausente → `{ "valid": false, "error": "<mensaje>" }` · `500` error inesperado.
- **Lo usan los 7 módulos restantes** para comprobar sesión y rol. No decodifiquéis el token por vuestra cuenta: llamad a este endpoint.

### `GET /secrets/{clave}`
- **Request:** cabecera `Authorization: Bearer <jwt de servicio>` y la clave en la ruta.
- **Response `200`:**
  ```json
  { "clave": "api_key", "valor": "<valor descifrado>" }
  ```
  La respuesta lleva `Cache-Control: no-store`.
- **Errores:** `400` clave no válida · `401` token inválido o ausente · `403` token válido pero rol distinto de `servicio` · `404` clave inexistente · `500` error inesperado.
- Solo para llamadas autenticadas como rol "servicio".
- Cada acceso (concedido o denegado) queda en el registro de auditoría.

### `GET /audit` (novedad 1.1.0)
- **Request:** cabecera `Authorization: Bearer <jwt de admin>`. Parámetros opcionales de consulta: `event_type`, `result`, `username` (coincidencia exacta), `from` y `to` (fechas UTC, formato `2026-10-22T00:00:00Z`), `limit` (1-200, por defecto 50) y `offset` (por defecto 0).
- **Response `200`** (eventos del más reciente al más antiguo; si no hay ninguno, `logs` vacío y `total` 0):
  ```json
  {
    "logs": [
      {
        "event_id": "g1-log-1792681201000-1",
        "timestamp": "2026-10-22T15:00:01Z",
        "source": "identity",
        "event_type": "login_ok",
        "result": "ok",
        "source_ip": "10.0.0.15",
        "details": { "username": "analista1", "role": "analista", "source_port": 51234, "clave": null }
      }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
  }
  ```
- **Tipos de evento (`event_type`):** `login_ok`, `login_failed`, `invalid_user`, `secret_read`, `secret_denied`. `result` vale `ok` o `fail`.
- **Errores:** `400` parámetro de consulta no válido · `401` token inválido, expirado o ausente · `403` token válido pero rol distinto de `admin` · `500` error inesperado. Cuerpo: `{ "error": "<mensaje>" }`.
- `source_ip` es la IP de la conexión (no se lee `X-Forwarded-For`). En `details`, las claves siempre están presentes y valen `null` cuando no aplican.
- El registro **nunca** contiene contraseñas, tokens ni valores de secretos (en `clave` solo va el nombre del secreto).
- Mocks de las respuestas en `modules/01-identidad/mocks/`: `audit_response.json`, `audit_empty.json` y `audit_errors.json`.

### Endpoints adicionales

- `POST /auth/register`: registro de un usuario con rol `analista`.
  - Request: `{ "username", "password" (mínimo 8 caracteres), "email" }`.
  - Response `201`: igual que el login (`token` y `user`). Errores: `400` datos no válidos · `409` usuario o email ya existentes.
- `GET /health`: estado del servicio (`{ "status": "ok", "module": "01-identidad" }`). Lo usa el CI.

## Roles

Valores exactos, en minúsculas:

- `admin`: único rol que puede consultar `GET /audit`.
- `analista`: rol de los usuarios registrados con `POST /auth/register`.
- `servicio`: cuentas precargadas para los módulos; es el único rol que puede leer secretos.

## Cómo usarlo desde tu módulo

1. El usuario obtiene un token con `POST /auth/login` (o `POST /auth/register`).
2. Cada petición a tu API llega con `Authorization: Bearer <jwt>`.
3. Tu módulo llama a `GET /auth/validate` con ese mismo token:
   - `200` → continuar según el `role` devuelto.
   - `401` → rechazar la petición.

Ejemplo (en Windows PowerShell usad `curl.exe`):

```
curl http://localhost:8001/auth/validate -H "Authorization: Bearer <jwt>"
```

## Token

- JWT firmado con HS256. Claims: `sub` (usuario), `role`, `user_id`, `iat`, `exp`. Caducidad: 30 minutos.
- La clave de firma no sale del módulo 1: por eso se valida llamando a `/auth/validate`.

## Secretos y cuentas de servicio

- Las cuentas de servicio son precargadas. **Pedid las credenciales por Teams al equipo 01** y guardadlas en variables de entorno o en un `.env` ignorado por Git. **El repositorio es público: no subáis credenciales reales.**

## Mock para programar sin esperarnos

```
npx @stoplight/prism-cli mock modules/01-identidad/contract/openapi.yaml -p 4010
```

Responde con los ejemplos del contrato. Cualquier equipo puede levantarlo con ese comando en cuanto se fusione el PR del contrato.

## Pendiente de confirmar

- Que el rol `admin` no necesite leer secretos (a confirmar con el profesorado).
- Límite de intentos de login y rotación manual de secretos (Sprints 2 y 3).

## Contacto

Equipo 01 · CypherGate. Jira: proyecto AAA. Dudas o cambios por Teams y por Pull Request.
