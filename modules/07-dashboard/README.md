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
Sprint 1: página estática (nginx) que lista las alertas del SIEM ordenadas por severidad y las refresca cada 30 s. Lee el mock `mocks/siem-alerts.json`; el SIEM real se conectará cuando esté disponible. `GET /health` responde `200`.

## Historias implementadas (Sprint 1)
| Historia | Qué hace | Limitaciones |
|---|---|---|
| DASHG7-22 · Listado de alertas del SIEM | Tabla con severidad, título, módulo y hora, ordenada por severidad y fecha. Muestra un mensaje de error si no hay datos. | Lee el mock `mocks/siem-alerts.json`; el SIEM real aún no está conectado. |
| DASHG7-25 · Refresco periódico de datos | Vuelve a pedir las alertas cada 30 s y muestra la hora de la última actualización. | Refresco simple (sin websockets), como indica el enunciado. |

Pendiente para el Sprint 2: login contra Identidad (DASHG7-19; ahora se envía un token de prueba), cierre de sesión, detalle de alerta, hallazgos del escáner y aviso de datos no actualizados.

## Cómo probarlo
```bash
cp .env.example .env
docker compose up --build dashboard
```
Abrid `http://localhost:8007` y comprobad `curl -f http://localhost:8007/health`.

Para hacerlo todo de una vez (arranca, comprueba y limpia al terminar, sin tocar vuestro `.env`):
```bash
bash modules/07-dashboard/scripts/probar.sh
```
