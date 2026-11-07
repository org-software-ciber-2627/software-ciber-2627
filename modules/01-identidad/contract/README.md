# Contrato del módulo 1 - Identidad y secretos

Equipo 01 - CypherGate. 

Fuente de verdad del contrato: [`openapi.yaml`](./openapi.yaml).
Resumen para los demás módulos: [`shared/auth-contract.md`](../../../shared/auth-contract.md).

## Qué hay en esta carpeta

| Fichero | Contenido |
|---|---|
| `openapi.yaml` | Contrato OpenAPI 3.0.3 de los endpoints del módulo |
| `../mocks/` | Mocks y ejemplos para que los demás equipos programen sin esperar al servicio real |

## Endpoints

| Método y ruta | Quién lo usa | Descripción |
|---|---|---|
| `GET /health` | CI y docker-compose | Estado del servicio (200) |
| `POST /auth/register` | Usuarios | Alta de usuario con rol `analista`; devuelve JWT |
| `POST /auth/login` | Usuarios | Login; devuelve JWT |
| `GET /auth/validate` | Los otros 7 módulos | Valida un token y devuelve usuario y rol |
| `GET /secrets/{clave}` | Solo rol `servicio` | Devuelve un secreto descifrado |

## Cómo verlo, comprobarlo y probarlo

Los comandos requieren Node.js.

- **Ver el contrato:** pegar `openapi.yaml` en <https://editor.swagger.io>.
- **Comprobar que es válido:** `npx @redocly/cli lint modules/01-identidad/contract/openapi.yaml`
- **Levantar un mock con los ejemplos del contrato:**
  `npx @stoplight/prism-cli mock modules/01-identidad/contract/openapi.yaml -p 4010`
  y probar, por ejemplo, `curl http://localhost:4010/health`.

## Decisiones del Sprint 1 (v1.0.2)

| Tema | Decisión | Cambio |
|---|---|---|
| Token | JWT HS256, caducidad 30 min | Se avisa por PR y Teams |
| Roles | `admin`, `analista`, `servicio` (los de `shared/auth-contract.md`) | Se avisa por PR y Teams |
| Identificador de usuario | Entero en todo el contrato (`id` y `user_id`) | — |
| Acceso a secretos | Solo rol `servicio` | Pendiente de confirmar con el profesorado |
| Validación desde otros módulos | Siempre llamando a `GET /auth/validate` | — |

## Cómo proponer cambios

1. Abrir un Pull Request modificando `openapi.yaml` con la clave de Jira en el título (por ejemplo `AAA-NN`).
2. Avisar por Teams a los equipos que consumen el endpoint afectado.
3. Esperar su confirmación antes de fusionar si el cambio rompe compatibilidad.

## Historial

- **1.0.2** (10/10/2026): el rol de los usuarios registrados pasa de `normal` a `analista`, para coincidir con los roles de `shared/auth-contract.md` (`admin`, `analista`, `servicio`).
- **1.0.1** (10/10/2026): se añade `GET /health`, se unifica el tipo del identificador, se restringe `/secrets/{clave}` al rol `servicio` y se documenta el JWT.
- **1.0.0**: versión inicial con login, registro, validación y secretos.