# Módulo 7 · Panel de control (Dashboard)

- **Equipo propietario:** `equipo-07-dashboard` (nosotros)
- **Puerto:** `8007`

## Qué expone
Nada: es el último eslabón de la cadena. Interfaz única que visualiza alertas, incidentes, hallazgos y actividad del Honeypot.

## Qué consume
- Identidad y secretos (login).
- SIEM (`GET /alerts`).
- SOAR (`GET /incidents`).
- Escáner (histórico de hallazgos, si está disponible).

## Responsabilidad adicional
Este equipo mantiene la infraestructura de integración compartida: el `docker-compose.yml` raíz y el pipeline de CI (`.github/workflows/ci.yml`). Los Pull Requests a `main` solo los aprueban los representantes de equipo (`@org-software-ciber-2627/reps`): este equipo garantiza que el CI y la infraestructura existen y funcionan, **no aprueba ni bloquea el trabajo ajeno**.

## Estado
Sprint 1: página estática (nginx) que lista las alertas del SIEM ordenadas por severidad y las refresca cada 30 s. En el Sprint 1 leía el mock `mocks/siem-alerts.json`. Desde el Sprint 2 (DASHG7-103 y DASHG7-104) pide las alertas al propio Dashboard en `/api/siem/alerts`, y el nginx las reenvía al SIEM real (`http://siem:80/alerts`, solo GET). Se usa el proxy porque el SIEM no tiene CORS. Si el SIEM no está levantado, la web muestra su mensaje de error. `GET /health` responde `200`.

## Historias implementadas
| Historia | Qué hace | Limitaciones |
|---|---|---|
| DASHG7-22 · Listado de alertas del SIEM | Tabla con severidad, título, módulo y hora, ordenada por severidad y fecha. | En el Sprint 1 leía el mock `mocks/siem-alerts.json`; desde el Sprint 2 lee el SIEM real a través del proxy de nginx. |
| DASHG7-25 · Refresco periódico de datos | Vuelve a pedir las alertas cada 30 s y muestra la hora de la última actualización. | Refresco simple (sin websockets), como indica el enunciado. |
| DASHG7-23 · Detalle de una alerta | «Ver detalle» en cada fila muestra todos los campos de la alerta (`GET /alerts/{id}` del SIEM, también por el proxy). | El SIEM no ofrece eventos relacionados, así que el detalle se limita a los campos de la alerta. |
| DASHG7-26 · Listado de incidentes | Tabla «Incidentes del SOAR» con identificador, alerta de origen, estado y playbook aplicado. | Lee el mock `mocks/soar-incidents.json`, no el SOAR real: hace falta un proxy de nginx hacia el SOAR cuando su API llegue a `main`. |
| DASHG7-67 · Estados de error y de datos vacíos | Cada tabla muestra un aviso distinto si el servicio no responde, no hay datos, no hay permiso o la respuesta no tiene el formato esperado. | El aviso de datos no actualizados (DASHG7-36) queda para el Sprint 3. |
| DASHG7-19 / DASHG7-47 · Login contra Identidad | `login.html` consulta a Identidad (`POST /auth/login`) a través del proxy `/api/identidad/` de nginx, que solo deja pasar login, validate y logout. El token JWT se guarda en `sessionStorage` y se valida con `GET /auth/validate` al abrir el Dashboard; sin sesión válida, o con Identidad caída, redirige al login. Gestiona el 429 con cuenta atrás. | El botón «Cerrar Sesión» solo borra el token del navegador: todavía no lo revoca en Identidad. |

Pendiente: cierre de sesión contra Identidad, detección de un token caducado mientras se usa el Dashboard (DASHG7-20), hallazgos del escáner y aviso de datos no actualizados.

## Cómo probarlo
```bash
cp .env.example .env
docker compose up --build dashboard
```
Abrid `http://localhost:8007`: si no existe una sesión válida, redirige a `login.html`. Iniciad sesión con una cuenta válida del servicio Identidad para acceder a las alertas. Comprobad también `curl -f http://localhost:8007/health`.

Para hacerlo todo de una vez (arranca, comprueba y limpia al terminar, sin tocar vuestro `.env`), con Docker en marcha:

| Sistema | Comando (desde la raíz del clon) |
|---|---|
| Linux y macOS | `bash modules/07-dashboard/scripts/probar.sh` |
| Windows (PowerShell) | `powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1` |

**Nota:** Las opciones de los scripts se escriben por separado (`-s -m`, no `-sm`). En PowerShell se utilizan igual.

| Opción | Qué hace |
|---|---|
| `-s` | No reconstruye las imágenes: usa las existentes. Tras un `git pull` con cambios, ejecuta antes sin opciones. |
| `-m` | Al terminar deja todo levantado, sin esperar a Enter. |
| `-c` | Solo comprueba lo que ya está corriendo, sin arrancar nada. |
| `-p` | Para y borra lo que dejó `-m`. No hace pruebas. |
| `-n` | No arranca ni comprueba los mocks de SOAR y Escáner. |
| `-h` | Muestra la ayuda. |

## Pruebas automáticas (DASHG7-66)
Las pruebas del front usan el ejecutor integrado de Node (`node --test`) y `jsdom` para simular el navegador. El Dashboard sigue siendo estático: `package.json` solo existe para las pruebas y no entra en la imagen de Docker.

| Fichero | Qué comprueba |
|---|---|
| `tests/siem-client.test.js` | Cliente del SIEM: envía el token como `Bearer`, devuelve siempre `{ estado, datos, mensaje }` (ok, vacío, error o sin permiso), y ante un 401 borra el token y redirige al login. |
| `tests/siem-alert.test.js` | Tabla de alertas sobre el `index.html` real: orden por severidad y fecha, escapado de HTML, estado de error, refresco cada 30 s. |
| `tests/mock-siem.test.js` | El mock `mocks/siem-alerts.json` mantiene los campos y valores que el Dashboard necesita. |

Para ejecutarlas en local hace falta Node 20 o superior (no hace falta Docker):
```bash
cd modules/07-dashboard
npm ci      # la primera vez
npm test
```
En el CI se ejecutan en el job `dashboard-tests` de `.github/workflows/ci.yml` en cada Pull Request a `main`.
