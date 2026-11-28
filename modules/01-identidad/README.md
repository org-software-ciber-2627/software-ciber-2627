# Módulo 1 - Identidad y secretos (IAM + gestor de secretos)

Equipo 01 - **CypherGate**

Servicio transversal del que dependen los otros 7 módulos: **autenticación, roles y almacén de secretos**.

## Estado (Sprint 3)

| Elemento | Estado |
|---|---|
| Contrato de la API (`contract/openapi.yaml`) | Publicado, v1.4.0 |
| Resumen para los demás equipos (`shared/auth-contract.md`) | Publicado |
| `POST /auth/register` y `POST /auth/login` (JWT HS256, 30 min) | Implementados |
| Límite de intentos de login (5 fallos en 15 min por usuario e IP; `429` con `Retry-After`) | Implementado |
| `GET /auth/validate` | Implementado |
| `POST /auth/logout` (revoca el token por su `jti`) | Implementado |
| `GET /secrets/{clave}` (AES-GCM; cada secreto solo lo lee la cuenta de servicio dueña, `403` para las demás) | Implementado |
| Una cuenta de servicio por módulo (`svc-*`, desde variables de entorno; nombres reservados en el registro) | Implementado |
| Secreto `siem_db_password` para el SIEM (dueño `svc-siem`) | Implementado |
| Registro de auditoría interno y envío de logs al IDS (`POST /logs` del módulo 2, lotes de hasta 200, con reintentos si el IDS cae) | Implementado |
| CORS para el Dashboard (`http://localhost:8007`, en login, register, validate y logout) | Implementado |
| Rotación manual de secretos | Sprint 3 |

> Este README se actualiza en cada Pull Request que cambie el comportamiento del módulo.

## Qué hace

- Registro e inicio de sesión de usuarios y emisión de un **JWT**.
- **Roles fijos:** `admin`, `analista`, `servicio`.
- **Validación de token** para que el resto de módulos compruebe sesión y rol (`GET /auth/validate`).
- **Cuentas de servicio por módulo** (`svc-ids`, `svc-siem`…), creadas solo desde variables de entorno.
- **Almacén de secretos** clave-valor cifrado en reposo (AES-256-GCM). Cada secreto tiene una cuenta dueña y solo ella lo lee. Rotación manual prevista en el Sprint 3.
- **Registro de auditoría interno** de los intentos de login y de los accesos a secretos. No se consulta por la API: se envía al IDS en lotes (`source` `01-identidad`), con líneas syslog al estilo OpenSSH, ids estables y orden cronológico. Si el IDS no responde, los eventos quedan pendientes y se reintentan con espera creciente sin bloquear el login.

**Fuera de alcance:** SSO con proveedores externos, MFA, rotación automática de secretos y permisos más finos que el dueño de cada secreto.

## Endpoints

| Método y ruta | Quién lo usa | Descripción |
|---|---|---|
| `GET /health` | CI y docker-compose | Estado del servicio |
| `POST /auth/register` | Usuarios | Alta de usuario con rol `analista`; devuelve JWT |
| `POST /auth/login` | Usuarios | Login; devuelve JWT. `429` tras 5 fallos seguidos |
| `POST /auth/logout` | Usuarios | Revoca el token actual |
| `GET /auth/validate` | Los otros 7 módulos | Valida un token y devuelve usuario y rol |
| `GET /secrets/{clave}` | La cuenta de servicio dueña del secreto | Devuelve un secreto descifrado (`403` si es de otro módulo) |

Detalle completo y códigos de error: [`contract/openapi.yaml`](./contract/openapi.yaml) y [`shared/auth-contract.md`](../../shared/auth-contract.md).

## Cómo consultar los endpoints (ejemplos)

Base URL en local: `http://localhost:8001`. En Windows PowerShell usad `curl.exe` en lugar de `curl`.

**Estado del servicio**

```
curl http://localhost:8001/health
```
Respuesta `200`: `{ "status": "ok", "module": "01-identidad" }`

**Registro** (rol `analista`)

```
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario.ejemplo","password":"contraseña-de-ejemplo","email":"usuario.ejemplo@ciberurjc.local"}'
```
Respuesta `201`: `{ "token": "<jwt>", "user": { "id": 1, "username": "usuario.ejemplo", "email": "usuario.ejemplo@ciberurjc.local", "role": "analista" } }`
Errores: `400` datos incompletos o no válidos; `409` usuario o email ya existentes.

**Login**

```
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario.ejemplo","password":"contraseña-de-ejemplo"}'
```
Respuesta `200`: `{ "token": "<jwt>", "user": { ... } }`
Errores: `400` falta usuario o contraseña; `401` credenciales incorrectas; `429` demasiados intentos (cabecera `Retry-After`).

**Validar un token** (lo usan los otros módulos)

```
curl http://localhost:8001/auth/validate -H "Authorization: Bearer <jwt>"
```
Respuesta `200`: `{ "valid": true, "user_id": 1, "username": "usuario.ejemplo", "role": "analista" }`
Error `401`: `{ "valid": false, "error": "Token inválido" }`

**Leer un secreto** (solo con un token de rol `servicio`)

```
curl http://localhost:8001/secrets/api_key -H "Authorization: Bearer <jwt-de-servicio>"
```
Respuesta `200`: `{ "clave": "api_key", "valor": "<valor descifrado>" }`
Errores: `401` token inválido; `403` rol distinto de `servicio`; `404` clave inexistente.

Para probar sin el servicio real, levantad el mock con los ejemplos del contrato:
`npx @stoplight/prism-cli mock modules/01-identidad/contract/openapi.yaml -p 4010` y usad el puerto 4010 en lugar del 8001.

## Estructura de la carpeta

```
modules/01-identidad/
├── README.md        Este fichero
├── contract/        Contrato OpenAPI (openapi.yaml) y su README
├── mocks/           Mocks para que otros equipos programen sin esperarnos
├── src/             Código fuente del servicio
└── Dockerfile       Imagen del servicio (puerto interno 80)
```

## Cómo arrancarlo

Desde la raíz del monorepo:

```
docker compose up --build
```

Comprobación:

```
curl http://localhost:8001/health
```

Debe responder `200`. El servicio escucha en el **puerto interno 80** (puerto externo 8001): no se debe cambiar, porque el CI y el compose dependen de ello.

## Configuración

Los valores sensibles se leen de **variables de entorno**, nunca del código. El repositorio es **público**: no se suben credenciales, claves ni tokens reales. Se usa un `.env` ignorado por Git y se documentan los nombres en `.env.example` sin valores reales.

| Variable | Para qué |
|---|---|
| `JWT_SECRET_KEY` | Clave de firma del JWT (HS256). Obligatoria para login, registro, validate y secretos |
| `AES_KEY` | Clave AES-256 en base64 de 32 bytes. Obligatoria para `/secrets` |
| `ADMIN_PASSWORD` | Si existe, se crea la cuenta `admin` |
| `SERVICE_PASSWORD` | **Transitoria.** Si existe, se crea la cuenta compartida `servicio` (la usan hoy IDS y el CI del SIEM) |
| `SERVICE_PASSWORD_IDS`, `_HONEYPOT`, `_ESCANER`, `_PENTESTING`, `_SOAR`, `_SIEM` | Si existen, se crean las cuentas de rol `servicio` `svc-ids`, `svc-honeypot`, `svc-escaner`, `svc-pentesting`, `svc-soar` y `svc-siem`. Esos nombres no se pueden registrar (`409`) |
| `SECRET_SIEM_DB_PASSWORD` | Si existe, se guarda cifrado como secreto `siem_db_password`; solo lo lee `svc-siem` |
| `SECRET_DB_PASSWORD`, `SECRET_API_KEY`, `SECRET_JWT_SECRET` | Si existen, se guardan cifrados como secretos de demostración; solo los lee `servicio` |
| `IDS_URL` | Destino del envío de logs (por defecto `http://ids/logs`) |
| `IDS_RETRY_SECONDS` | Espera base entre reintentos al IDS (por defecto 30 s, con tope de 300 s) |
| `IDS_REINTENTOS` | `0` desactiva el hilo de reintentos (solo para pruebas) |
| `TRUSTED_PROXY_HOPS`, `JWT_EXPIRES_SECONDS`, `DATABASE_URL` | Opcionales |

### Cargar las cuentas y los secretos

Las contraseñas y los valores de los secretos **nunca** se escriben en el código, el compose ni el repositorio:

1. Copiad `.env.example` a `.env` en la raíz del monorepo (`.env` está en `.gitignore`).
2. Rellenad `JWT_SECRET_KEY`, `AES_KEY` y, para cada cuenta o secreto que haga falta, su `SERVICE_PASSWORD_*` o `SECRET_*`. Generad valores aleatorios, por ejemplo con `python -c "import secrets; print(secrets.token_urlsafe(24))"`; para `AES_KEY`, `python -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"`.
3. Arrancad con `docker compose up --build`. Al iniciar, Identidad crea las cuentas y guarda cada secreto **cifrado con AES-256-GCM** en la base de datos, con su cuenta dueña. Una variable vacía no crea nada.
4. Comprobad que funciona haciendo login con la cuenta y leyendo su secreto (ver [`shared/auth-contract.md`](../../shared/auth-contract.md#cómo-leer-un-secreto-desde-vuestro-módulo)).
5. Entregad cada contraseña de cuenta a su módulo **por mensaje privado**.

Cómo piden los demás módulos su cuenta y leen sus secretos: [`shared/auth-contract.md`, sección «Secretos y cuentas de servicio»](../../shared/auth-contract.md#secretos-y-cuentas-de-servicio).

## Pruebas

El módulo dispone de pruebas automáticas para comprobar el funcionamiento de los endpoints y la lógica del servicio de identidad.

Para ejecutar las pruebas desde la raíz del monorepo, utiliza:

```
python -m unittest discover -s modules/01-identidad/tests -p 'test_*.py'
```

Las pruebas se ejecutan también automáticamente mediante GitHub Actions cuando se realizan los eventos configurados en el workflow de CI (`.github/workflows/ci.yml`).

Antes de fusionar un Pull Request, el CI debe finalizar correctamente. Si alguna prueba falla, el trabajo de CI se marcará como fallido y será necesario corregir el problema antes de fusionar los cambios.

## Cómo contribuir

1. Rama `equipo-01-identidad` (o `equipo-01-identidad/AAA-NN-descripcion` si se renombra la rama base), con la clave de Jira en los commits.
2. Pull Request a `main` con la clave Jira en el título, la checklist de Definition of Done y CI en verde.
3. Revisión por otra persona. Los PRs de este módulo los revisa el equipo 8 (Pentesting).
4. Si el PR cambia el contrato, avisar por Teams a los equipos consumidores.

## Equipo

CypherGate: Diego (Product Owner), Ainoa (Scrum Master), Omar, Nerea, Jaime y Natalia (equipo de desarrollo). Seguimiento en Jira, proyecto **AAA**.