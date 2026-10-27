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

## Historias implementadas (Sprint 1)
| Historia | Qué hace | Limitaciones |
|---|---|---|
| DASHG7-22 · Listado de alertas del SIEM | Tabla con severidad, título, módulo y hora, ordenada por severidad y fecha. Muestra un mensaje de error si no hay datos. | En el Sprint 1 leía el mock `mocks/siem-alerts.json`; desde el Sprint 2 lee el SIEM real a través del proxy de nginx. |
| DASHG7-25 · Refresco periódico de datos | Vuelve a pedir las alertas cada 30 s y muestra la hora de la última actualización. | Refresco simple (sin websockets), como indica el enunciado. |

Avance parcial (maqueta, **no** es la historia DASHG7-19 terminada): `login.html` con formulario de usuario y contraseña (DASHG7-46) y un botón «Cerrar Sesión» en la página principal. El login **no consulta a Identidad**: acepta cualquier usuario y contraseña y guarda un token de prueba en `sessionStorage`. Es solo una protección de interfaz, no autenticación real.

Pendiente para el Sprint 2: login real contra Identidad (DASHG7-19 y DASHG7-47) con expiración del token (DASHG7-20), detalle de alerta, hallazgos del escáner y aviso de datos no actualizados.

## Cómo probarlo
```bash
cp .env.example .env
docker compose up --build dashboard
```
Abrid `http://localhost:8007`: redirige a `login.html`; entrad con cualquier usuario y contraseña y se mostrarán las alertas. Comprobad también `curl -f http://localhost:8007/health`.

Para hacerlo todo de una vez (arranca, comprueba y limpia al terminar, sin tocar vuestro `.env`), con Docker en marcha:

| Sistema | Comando (desde la raíz del clon) |
|---|---|
| Linux y macOS | `bash modules/07-dashboard/scripts/probar.sh` |
| Windows (PowerShell) | `powershell -ExecutionPolicy Bypass -File modules\07-dashboard\scripts\probar.ps1` |
