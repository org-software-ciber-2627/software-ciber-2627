# Contrato de autenticación (Identidad y secretos)

El equipo `equipo-01-identidad` publica aquí el contrato de los endpoints que expone.
La fuente de verdad es [`modules/01-identidad/contract/openapi.yaml`](../modules/01-identidad/contract/openapi.yaml)
(versión 1.4.0); si este resumen y el YAML difieren, manda el YAML. Los cambios se hacen por Pull Request
y se avisan por Teams a los equipos que usen el endpoint.

Servicio en local con `docker compose up`: `http://localhost:8001` (puerto interno `80` dentro del compose).

**Historial.** 
1.4.0: una cuenta de servicio por módulo; pedir un secreto de otro módulo devuelve `403` y se registra `secret_denied`. 1.3.2: se documenta que el `404` de `/secrets` registra `secret_denied`, que la caducidad del JWT es configurable, que el 5.º fallo de login ya devuelve `429`, el envío al IDS en lotes de hasta 200 y el valor de `IDS_REINTENTOS`. 1.3.1: se documentan CORS, variables de entorno, el envío de logs al IDS y la auditoría de `/secrets`. 1.3.0: se retiran `GET /audit` (nunca se implementó) y `GET /logs` (existía en el código); ningún módulo los usa; se documentan el `429` del login y el evento `limit_exceeded`; CORS también en `GET /auth/validate` y `POST /auth/logout`. 1.2.0: se añade `POST /auth/logout` (cierre de sesión). 1.1.0: se añade `GET /audit` (registro de auditoría, solo `admin`). Todos son compatibles salvo 1.4.0, que deniega con `403` leer un secreto de otro módulo. 27/10: se documenta CORS para el Dashboard (sin cambios en los endpoints).

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
- **Errores:** `400` falta usuario o contraseña · `401` credenciales incorrectas · `429` demasiados intentos: el 5º fallo en 15 minutos ya devuelve `429` en lugar de `401`; bloqueo temporal por combinación de usuario e IP, con cabecera `Retry-After` indicando los segundos restantes · `500` error inesperado. Cuerpo: `{ "error": "<mensaje>" }`.
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
- **Request:** cabecera `Authorization: Bearer <jwt>` de la cuenta de servicio dueña del secreto y la clave en la ruta.
- **Response `200`:**
  ```json
  { "clave": "api_key", "valor": "<valor descifrado>" }
  ```
  La respuesta lleva `Cache-Control: no-store`.
- **Errores:** `400` clave no válida · `401` token inválido o ausente · `403` token válido pero rol distinto de `servicio` o el secreto pertenece a otro módulo · `404` clave inexistente · `500` error inesperado.
- Auditoría: el `200` se registra como `secret_read`; el `403` y el `404`, como `secret_denied`. El `401` no se registra (sin token válido no se sabe quién pide). Los eventos se envían al IDS y nunca contienen valores de secretos.

### Endpoints adicionales

- `POST /auth/register`: registro de un usuario con rol `analista`.
  - Request: `{ "username", "password" (mínimo 8 caracteres), "email" }`.
  - Response `201`: igual que el login (`token` y `user`). Errores: `400` datos no válidos · `409` usuario o email ya existentes o reservados (`admin`, `servicio`, `svc-*`).
- `GET /health`: estado del servicio (`{ "status": "ok", "module": "01-identidad" }`). Lo usa el CI.

## Roles

Valores exactos, en minúsculas:

- `admin`: cuenta de administración precargada, que se crea si existe `ADMIN_PASSWORD`; hoy no tiene endpoints propios.
- `analista`: rol de los usuarios registrados con `POST /auth/register`.
- `servicio`: una cuenta propia por módulo; es el único rol que puede leer secretos.

| Cuenta | Variable de entorno de su contraseña | Módulo |
|---|---|---|
| `svc-ids` | `SERVICE_PASSWORD_IDS` | 02 IDS |
| `svc-honeypot` | `SERVICE_PASSWORD_HONEYPOT` | 03 Honeypot |
| `svc-escaner` | `SERVICE_PASSWORD_ESCANER` | 04 Escáner |
| `svc-siem` | `SERVICE_PASSWORD_SIEM` | 05 SIEM |
| `svc-soar` | `SERVICE_PASSWORD_SOAR` | 06 SOAR |
| `svc-pentesting` | `SERVICE_PASSWORD_PENTESTING` | 08 Pentesting |
| `servicio` (**transitoria**) | `SERVICE_PASSWORD` | Compartida; se retirará cuando IDS y SIEM migren a su cuenta |

Cada cuenta solo existe si su variable está definida. Los nombres están reservados: `POST /auth/register` responde `409` con ellos.

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

- JWT firmado con HS256. Claims: `sub` (usuario), `role`, `user_id`, `iat`, `exp`. Caducidad: 30 minutos por defecto, configurable con `JWT_EXPIRES_SECONDS`.
- La clave de firma no sale del módulo 1: por eso se valida llamando a `/auth/validate`.

## Secretos y cuentas de servicio

Cada módulo tiene su cuenta con rol `servicio` y solo lee sus secretos. Todo secreto tiene un módulo dueño: pedir el de otro módulo devuelve `403`. Las cuentas están en la tabla de [Roles](#roles).

| Secreto | Variable de entorno | Cuenta dueña |
|---|---|---|
| `siem_db_password` | `SECRET_SIEM_DB_PASSWORD` | `svc-siem` |
| `db_password`, `api_key`, `jwt_secret` (demostración) | `SECRET_DB_PASSWORD`, `SECRET_API_KEY`, `SECRET_JWT_SECRET` | `servicio` (transitoria) |

**El repositorio es público: no subáis nunca contraseñas ni valores de secretos.** Van en variables de entorno o en un `.env` (ignorado por Git).

### Cómo pedir una cuenta de servicio

1. Escribid al equipo 01 por Teams indicando el módulo. Si vuestra cuenta ya está en la tabla de Roles, solo os falta la contraseña.
2. El equipo 01 os pasa la contraseña de vuestra cuenta **por mensaje privado**, nunca en un canal público ni en el repositorio.
3. Guardadla en vuestro `.env` con la variable de la tabla de Roles (por ejemplo `SERVICE_PASSWORD_SIEM=...`). Identidad crea la cuenta al arrancar si la variable existe.
4. ¿Vuestro módulo es nuevo o no aparece en la tabla? Pedidlo al equipo 01: se añade la cuenta y su variable en una versión nueva del contrato.

### Cómo pedir un secreto nuevo

Indicad al equipo 01 la clave (`^[A-Za-z0-9_.-]{1,100}$`) y la cuenta dueña. Se añade con su variable `SECRET_<CLAVE>` y su dueño en una versión nueva del contrato. El **valor** se entrega por mensaje privado a quien despliega (`.env`), nunca en el repositorio.

### Cómo leer un secreto desde vuestro módulo

1. Iniciad sesión con vuestra cuenta de servicio y guardad el token:

   ```
   curl -X POST http://localhost:8001/auth/login -H "Content-Type: application/json" -d "{\"username\": \"svc-siem\", \"password\": \"<contraseña de vuestro .env>\"}"
   ```

2. Pedid el secreto con ese token:

   ```
   curl http://localhost:8001/secrets/siem_db_password -H "Authorization: Bearer <jwt>"
   ```

   Respuesta `200`: `{ "clave": "siem_db_password", "valor": "<valor descifrado>" }`, con `Cache-Control: no-store`.

3. Usad el valor en memoria. No lo escribáis en logs, ficheros ni respuestas.

| Código | Qué significa | Qué hacer |
|---|---|---|
| `401` | Token ausente, caducado (30 min) o revocado | Volved a hacer login |
| `403` | La cuenta no es `servicio` o el secreto es de otro módulo | Revisad que usáis vuestra cuenta |
| `404` | El secreto no está cargado | Falta su variable `SECRET_*` en el `.env` de Identidad; avisad al equipo 01 |
| `500` | Falta `AES_KEY` o `JWT_SECRET_KEY` en Identidad | Avisad al equipo 01 |

Dentro del compose usad `http://identidad:80` en lugar de `http://localhost:8001`. En Windows PowerShell, `curl.exe`.

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
