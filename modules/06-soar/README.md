# Módulo 6 · Gestor de incidentes (SOAR ligero)

- **Equipo propietario:** `equipo-06-soar`
- **Puerto:** `8006`

## Qué expone
Registra incidentes a partir de las alertas del SIEM y automatiza una respuesta simple.
- `GET /incidents`

## Qué consume
- `GET /alerts` del SIEM.

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.
