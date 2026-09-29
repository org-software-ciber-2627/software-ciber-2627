# Módulo 5 · SIEM simplificado

- **Equipo propietario:** `equipo-05-siem`
- **Puerto:** `8005`

## Qué expone
Hub de correlación: ingiere eventos de IDS, Honeypot y Escáner, los correla y expone alertas priorizadas.
- `GET /alerts`
- `GET /alerts/{id}`

## Qué consume
- `POST /events` de IDS, Honeypot y Escáner (formato común de evento).

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.
