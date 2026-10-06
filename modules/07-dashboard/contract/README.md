# Contrato de API · Dashboard (consumidor)

El Dashboard no expone ninguna API que otros módulos consuman: es el último eslabón de la cadena. Este documento recoge las dependencias que consume y el estado de cada una. Los cuerpos de petición y respuesta los publica el equipo propietario de cada módulo; hasta entonces se marcan como **pendientes**.

## Expone

Nada.

## Consume

| Módulo | Endpoint | Uso en el Dashboard | Contrato |
|---|---|---|---|
| Identidad (`equipo-01-identidad`) | `POST /auth/login` | Login de usuarios | Ver `shared/auth-contract.md` (pendiente) |
| Identidad (`equipo-01-identidad`) | `GET /auth/validate` | Comprobar sesión y rol | Ver `shared/auth-contract.md` (pendiente) |
| SIEM (`equipo-05-siem`) | `GET /alerts` | Listado de alertas | _pendiente (lo publica SIEM)_ |
| SIEM (`equipo-05-siem`) | `GET /alerts/{id}` | Detalle de alerta | _pendiente (lo publica SIEM)_ |
| SOAR (`equipo-06-soar`) | `GET /incidents` | Listado de incidentes | _pendiente (lo publica SOAR)_ |
| Escáner (`equipo-04-escaner`) | Histórico de hallazgos | Vista de hallazgos (opcional) | _pendiente (Escáner decide si lo expone)_ |

Todas las llamadas se hacen contra la URL de la variable de entorno correspondiente (`SIEM_URL`, `SOAR_URL`, etc., ver `.env.example`), de forma que se puede apuntar a un mock o al servicio real sin tocar el código.

## Mocks

Mientras una dependencia no esté disponible, el Dashboard trabaja contra su propio mock en `modules/07-dashboard/mocks/`, con datos de ejemplo fijos que respetan el contrato publicado por el equipo propietario.

## Estado de integración

El Dashboard añade además una vista de "salud de integración" que consulta `GET /health` de cada módulo (`8001`–`8008`).
