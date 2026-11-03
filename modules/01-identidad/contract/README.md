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
| `POST /auth/logout` | Usuarios | Cierra la sesión: revoca el token con el que se llama |
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

## Decisiones del Sprint 2 (v1.3.0)

| Tema | Decisión | Cambio |
|---|---|---|
| Cierre de sesión | `POST /auth/logout` revoca el token. Con un token revocado, `validate` y `secrets` responden 401 | Compatible |
| Límite de intentos | 5 fallos en 15 minutos del mismo usuario y la misma IP bloquean el login: 429 con `Retry-After` | Compatible |
| Auditoría | Se registran login_ok, login_failed, invalid_user, limit_exceeded, secret_read y secret_denied. Nunca contraseñas, tokens ni valores de secretos | Compatible |
| Envío de logs al IDS | Ver la sección siguiente | Compatible |

## Envío de logs al IDS

Este módulo entrega al IDS (módulo 02) los eventos de auditoría, según el contrato del IDS
(`modules/02-ids/contract/`). No consume nada del IDS.

| Tema | Acuerdo |
|---|---|
| Destino | `POST` a `IDS_URL` (por defecto `http://ids/logs`), `Content-Type: application/json` |
| Autenticación | Ninguna (el contrato del IDS no la exige) |
| Cuerpo | `{"source": "01-identidad", "logs": [{"id": "...", "raw_line": "..."}]}` |
| Identificador | `g1-log-<milisegundos>-<fila>`: estable, el IDS descarta duplicados |
| Orden | Del evento más antiguo al más reciente |
| Tamaño del lote | Hasta 200 líneas por envío (el IDS admite hasta 1000) |
| Respuesta correcta | 200 o 202 |
| Línea | `MMM d HH:mm:ss host identidad[pid]: mensaje` |

Mensajes de cada evento (el puerto solo aparece si está disponible):

| Evento | Mensaje |
|---|---|
| login_ok | `Accepted password for <user> from <ip> port <puerto> ssh2` |
| login_failed | `Failed password for <user> from <ip> port <puerto> ssh2` |
| invalid_user | `Failed password for invalid user <user> from <ip> port <puerto> ssh2` |
| limit_exceeded | `authentication attempts exceeded from <ip> port <puerto>` |
| secret_read, secret_denied | `event=<tipo> result=<ok o fail> user=<user> from=<ip> clave=<clave>` |

Nunca se envían contraseñas, tokens ni valores de secretos.

**Funcionamiento.** Cada evento se guarda con `enviado = false` y un hilo en segundo plano envía
los pendientes, del más antiguo al más reciente, en lotes de hasta 200 y con un máximo de 2 s
de espera. El login y la lectura de secretos nunca esperan al IDS. Si el IDS no responde 200
o 202, los eventos quedan pendientes y un hilo de reintentos lo vuelve a intentar a los 30 s;
si siguen quedando eventos sin enviar (de más de 10 s), la espera se duplica hasta un máximo de
300 s. Un candado evita que dos procesos envíen a la vez.

**Variables de entorno:** `IDS_URL`, `IDS_RETRY_SECONDS` (30 por defecto) e `IDS_REINTENTOS`
(1 activa los reintentos, 0 los desactiva).

## Cómo proponer cambios

1. Abrir un Pull Request modificando `openapi.yaml` con la clave de Jira en el título (por ejemplo `AAA-NN`).
2. Avisar por Teams a los equipos que consumen el endpoint afectado.
3. Esperar su confirmación antes de fusionar si el cambio rompe compatibilidad.

## Historial

- 1.3.0 (03/11/2026): se documenta el envío de logs al IDS (cambio compatible, no modifica endpoints).
- 1.2.0 (fecha por completar): se añade `POST /auth/logout`.
- 1.1.0 (fecha por completar): se añade la consulta de auditoría.
- 1.0.2 (10/10/2026): el rol de los usuarios registrados pasa de normal a analista, para coincidir con los roles de `shared/auth-contract.md` (admin, analista, servicio).
- 1.0.1 (10/10/2026): se añade `GET /health`, se unifica el tipo del identificador, se restringe `/secrets/{clave}` al rol servicio y se documenta el JWT.
- 1.0.0: versión inicial con login, registro, validación y secretos.
