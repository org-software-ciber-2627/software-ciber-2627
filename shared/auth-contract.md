# Contrato de autenticación (Identidad y secretos)

El equipo `equipo-01-identidad` publica aquí, en el Sprint 1, el contrato de los endpoints que expone.
La fuente de verdad es [`modules/01-identidad/contract/openapi.yaml`](../modules/01-identidad/contract/openapi.yaml)
(versión 1.3.0); si este resumen y el YAML difieren, manda el YAML. Los cambios se hacen por Pull Request
y se avisan por Teams a los equipos que usen el endpoint.

Servicio en local con `docker compose up`: `http://localhost:8001` (puerto interno `80` dentro del compose).

**Historial.** 1.3.0: se retira `GET /audit` (nunca se implementó y no lo usa ningún módulo); se documentan el `429` del login y el evento `limit_exceeded`; CORS también en `GET /auth/validate` y `POST /auth/logout`. 1.2.0: se añade `POST /auth/logout` (cierre de sesión). 1.1.0: se añade `GET /audit` (registro de auditoría, solo `admin`). Ambos son cambios compatibles: no modifican los endpoints existentes. 27/10: se documenta CORS para el Dashboard (sin cambios en los endpoints).

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
- **Errores:** `400` falta usuario o contraseña · `401` credenciales incorrectas · `429` demasiados intentos; bloqueo temporal por combinación de usuario e IP, con cabecera `Retry-After` indicando los segundos restantes · `500` error inesperado. Cuerpo: `{ "error": "<mensaje>" }`.
- Cada intento de login queda en el registro de auditoría interno, que se envía al IDS. No hay endpoint para consultarlo.

### `POST /auth/logout` (novedad 1.2.0)
- **Request:** cabecera `Authorization: Bearer <jwt>`. Sin cuerpo.
- **Response `200`:**
  ```json
  { "message": "Token revocado" }
  ```
- **Errores:** `401` token inválido, expirado, revocado o ausente (también si ya se cerró la sesión con ese token) · `500` error inesperado. Cuerpo: `{ "error": "<mensaje>" }`.
- Tras el logout, ese token deja de valer: `GET /auth/validate` y `GET /secrets/{clave}` responden `401` con él. Los demás módulos no tienen que hacer nada: siguen validando con `GET /auth/validate`.

### `GET /auth/validate`
- **Request:** cabecera `Authorization: Bearer <jwt>`.
- **Response `200`:**
  ```json
  { "valid": true, "user_id": 1, "username": "usuario.ejemplo", "role": "analista" }
  ```
- **Errores:** `401` token inválido, expirado, revocado (tras un logout) o ausente → `{ "valid": false, "error": "<mensaje>" }` · `500` error inesperado.
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
- Cada acceso (concedido o denegado) queda en el registro de auditoría interno, que se envía al IDS. El registro nunca contiene valores de secretos.

### Endpoints adicionales

- `POST /auth/register`: registro de un usuario con rol `analista`.
  - Request: `{ "username", "password" (mínimo 8 caracteres), "email" }`.
  - Response `201`: igual que el login (`token` y `user`). Errores: `400` datos no válidos · `409` usuario o email ya existentes.
- `GET /health`: estado del servicio (`{ "status": "ok", "module": "01-identidad" }`). Lo usa el CI.

## Roles

Valores exactos, en minúsculas:

- `admin`: cuenta de administración precargada; hoy no tiene endpoints propios.
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

## CORS (llamadas desde el navegador)

Si vuestro módulo es una web que llama a esta API desde el navegador (como el Dashboard), la API tiene que aceptar su origen.

- **Origen permitido:** solo `http://localhost:8007` (el Dashboard en el compose). `http://127.0.0.1:8007` es otro origen distinto y no está permitido.
- **Endpoints con CORS:** `POST /auth/login`, `POST /auth/register`, `GET /auth/validate` y `POST /auth/logout`. Las respuestas de error (400, 401…) también llevan las cabeceras CORS, para que el navegador pueda leerlas.
- El navegador envía antes una petición `OPTIONS` (preflight); el servicio la responde.
- Se autentica con el token en la cabecera `Authorization` (permitida en el preflight), sin cookies.
- Está fijado en el código del módulo; no se configura por variable de entorno.
- **¿Necesitáis otro origen u otro endpoint?** Pedidlo por Teams al equipo 01 o por Pull Request.
- Solo afecta a las llamadas hechas desde un navegador; las llamadas entre servicios (por ejemplo, otro módulo llamando a `/auth/validate` desde su backend) no lo necesitan.

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
- Rotación manual de secretos (Sprint 3). El límite de intentos de login ya está implementado: 5 fallos en 15 minutos por usuario e IP.

## Contacto

Equipo 01 · CypherGate. Jira: proyecto AAA. Dudas o cambios por Teams y por Pull Request.
