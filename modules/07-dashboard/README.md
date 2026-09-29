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
Este equipo mantiene la infraestructura de integración compartida: el `docker-compose.yml` raíz y el pipeline de CI (`.github/workflows/ci.yml`). La revisión y fusión de Pull Requests a `main` sigue siendo rotatoria entre los 8 equipos: este equipo garantiza que el CI y la infraestructura existen y funcionan, **no aprueba ni bloquea el trabajo ajeno**.

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por la implementación real del Dashboard cuando esté lista.

<!-- prueba de proteccion de rama, PR descartable -->
