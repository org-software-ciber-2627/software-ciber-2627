# Módulo 1 - Identidad y secretos (IAM + gestor de secretos) - **CypherGate**

Servicio transversal del que dependen los otros 7 módulos: **autenticación, roles y almacén de secretos**.

## Estado (Sprint 1)

| Elemento | Estado |
|---|---|
| Contrato de la API (`contract/openapi.yaml`) | Publicado, v1.0.1 |
| Resumen para los demás equipos (`shared/auth-contract.md`) | Publicado |
| `GET /health` | Responde 200 (placeholder de la infraestructura del monorepo) |
| Registro y login con JWT | En desarrollo |
| Validación de token | Contrato definido; implementación en el Sprint 2 |
| Secretos cifrados y registro de accesos | Sprint 2 |
| Rotación manual de secretos y mínimo privilegio | Sprint 3 |

> Este README se actualiza en cada Pull Request que cambie el comportamiento del módulo.

## Qué hace

- Registro e inicio de sesión de usuarios y emisión de un **JWT**.
- **Roles fijos:** `normal`, `admin`, `servicio`.
- **Validación de token** para que el resto de módulos compruebe sesión y rol (`GET /auth/validate`).
- **Almacén de secretos** clave-valor cifrado en reposo, con rotación manual, accesible solo al rol `servicio`.
- **Registro de accesos** a secretos (qué servicio pidió qué secreto y cuándo).

**Fuera de alcance:** SSO con proveedores externos, MFA, rotación automática de secretos y permisos granulares por recurso.

## Endpoints

| Método y ruta | Quién lo usa | Descripción |
|---|---|---|
| `GET /health` | CI y docker-compose | Estado del servicio |
| `POST /auth/register` | Usuarios | Alta de usuario con rol `normal`; devuelve JWT |
| `POST /auth/login` | Usuarios | Login; devuelve JWT |
| `GET /auth/validate` | Los otros 7 módulos | Valida un token y devuelve usuario y rol |
| `GET /secrets/{clave}` | Solo rol `servicio` | Devuelve un secreto descifrado |

Detalle completo y códigos de error: [`contract/openapi.yaml`](./contract/openapi.yaml) y [`shared/auth-contract.md`](../../shared/auth-contract.md).

## Cómo consultar los endpoints (ejemplos)

Base URL en local: `http://localhost:8001`. En Windows PowerShell usad `curl.exe` en lugar de `curl`.

**Estado del servicio**

```
curl http://localhost:8001/health
```
Respuesta `200`: `{ "status": "ok", "module": "01-identidad" }`

**Registro** (rol `normal`)

```
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario.ejemplo","password":"contraseña-de-ejemplo","email":"usuario.ejemplo@ciberurjc.local"}'
```
Respuesta `201`: `{ "token": "<jwt>", "user": { "id": 1, "username": "usuario.ejemplo", "email": "usuario.ejemplo@ciberurjc.local", "role": "normal" } }`
Errores: `400` datos incompletos o no válidos; `409` usuario o email ya existentes.

**Login**

```
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"usuario.ejemplo","password":"contraseña-de-ejemplo"}'
```
Respuesta `200`: `{ "token": "<jwt>", "user": { ... } }`
Errores: `400` falta usuario o contraseña; `401` credenciales incorrectas.

**Validar un token** (lo usan los otros módulos)

```
curl http://localhost:8001/auth/validate -H "Authorization: Bearer <jwt>"
```
Respuesta `200`: `{ "valid": true, "user_id": 1, "username": "usuario.ejemplo", "role": "normal" }`
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
├── Dockerfile       Imagen del servicio (puerto interno 80)
└── default.conf     Configuración de nginx del placeholder inicial (se sustituirá al implementar el servicio real)
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

| Variable | Para qué | Estado |
|---|---|---|
| `[completar: JWT_SECRET]` | Clave de firma del JWT (HS256) | Propuesta de nombre |
| `[completar: SECRETS_KEY]` | Clave AES para cifrar los secretos | Propuesta de nombre |

## Pruebas

```
[completar: comando de pruebas del equipo]
```

Los tests de los endpoints se añaden con cada historia. El CI del monorepo debe quedar en verde antes de fusionar.

## Cómo contribuir

1. Rama `equipo-01-identidad`.
2. Pull Request a `main` con la clave Jira en el título, la checklist de Definition of Done y CI en verde.
3. Revisión por otra persona. Los PRs de este módulo los revisa el equipo 8 (Pentesting).
4. Si el PR cambia el contrato, avisar por Teams a los equipos consumidores.

## Equipo

CypherGate: Ainoa (delegada de Product Owner), Nerea (Scrum Master), Natalia, Jaime, Omar y Diego (equipo de desarrollo). Seguimiento en Jira, proyecto **AAA**.