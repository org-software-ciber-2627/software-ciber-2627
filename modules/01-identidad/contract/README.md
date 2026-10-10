# Contrato de autenticación

**Versión:** 1.0.1 - Sprint 1
**Fuente de verdad:** [`modules/01-identidad/contract/openapi.yaml`](../modules/01-identidad/contract/openapi.yaml). Si este resumen y el YAML difieren, manda el YAML.
**Cambios:** por Pull Request, con aviso por Teams a los equipos que usen el endpoint.

## 1. Dónde está el servicio

- Desde tu máquina con `docker compose up`: `http://localhost:8001`
- Entre contenedores del compose: el nombre del servicio del módulo 1 en `docker-compose.yml`, puerto interno `80`.

## 2. Endpoints

| Método y ruta | Auth | Para qué |
|---|---|---|
| `GET /health` | No | Estado del servicio (lo usa el CI) |
| `POST /auth/register` | No | Alta de usuario (rol `normal`) |
| `POST /auth/login` | No | Login; devuelve un JWT |
| `GET /auth/validate` | `Bearer` | **Lo usan los 7 módulos** para comprobar sesión y rol |
| `GET /secrets/{clave}` | `Bearer` con rol `servicio` | Devuelve un secreto descifrado |

## 3. Cómo usarlo desde tu módulo

1. El usuario o servicio obtiene un token con `POST /auth/login`:

   ```
   curl -X POST http://localhost:8001/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"usuario.ejemplo","password":"contraseña-de-ejemplo"}'
   ```

   Respuesta `200`: `{ "token": "<jwt>", "user": { "id": 1, "username": "...", "email": "...", "role": "normal" } }`

2. Cada petición a tu API llega con `Authorization: Bearer <jwt>`.
3. Tu módulo comprueba el token llamando a nuestro servicio **sin decodificarlo por su cuenta**:

   ```
   curl http://localhost:8001/auth/validate -H "Authorization: Bearer <jwt>"
   ```

   - `200`: `{ "valid": true, "user_id": 1, "username": "...", "role": "normal" }` → dejar pasar según el rol.
   - `401`: `{ "valid": false, "error": "..." }` → rechazar la petición.

## 4. Roles

| Rol | Cómo se obtiene en el Sprint 1 | Permisos |
|---|---|---|
| `normal` | Registro con `POST /auth/register` | Usuario del sistema |
| `admin` | Cuenta precargada | Administración |
| `servicio` | Cuenta precargada | Puede leer secretos con `GET /secrets/{clave}` |

Los nombres de rol son exactos y en minúsculas: comprobad ese valor literal.

## 5. Token

- JWT firmado con HS256. Claims: `sub` (usuario), `role`, `iat`, `exp`.
- Caducidad: 30 minutos.
- La clave de firma es secreta y no sale del módulo 1: por eso se valida llamando a `/auth/validate`.

## 6. Errores

- Formato general: `{ "error": "<mensaje>" }` con el código HTTP adecuado (400, 401, 403, 404, 409, 500).
- En `/auth/validate`: `{ "valid": false, "error": "<mensaje>" }`.

## 7. Secretos y cuentas de servicio

- `GET /secrets/{clave}` solo responde `200` al rol `servicio`. Con otro rol devuelve `403`.
- Las cuentas de servicio son precargadas. **Pedid las credenciales por Teams al equipo 01** y guardadlas en variables de entorno o en un `.env` ignorado por Git. **El repositorio es público: nunca subáis credenciales reales.**

## 8. Mock para programar sin esperarnos

Mientras el servicio real no esté terminado, levantad un mock con los ejemplos del contrato:

```
npx @stoplight/prism-cli mock modules/01-identidad/contract/openapi.yaml -p 4010
```

Disponible desde: **[completar fecha al publicar]**.

## 9. Pendiente o por confirmar

- Que admin no necesite leer secretos (pendiente de confirmar con el profesorado).
- Límite de intentos de login y rotación manual de secretos (Sprints 2 y 3).
- El formato común de evento (`shared/event-schema.json`) no afecta a este módulo, que no publica eventos.

## 10. Contacto

Equipo 01 - CypherGate. Jira: proyecto AAA. Dudas o peticiones de cambio por WhatsApp y por Pull Request.