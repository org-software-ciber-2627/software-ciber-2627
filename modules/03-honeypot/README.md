# Módulo 3 · Honeypot inteligente

- **Equipo propietario:** `equipo-03-honeypot`
- **Puerto:** `8003`

## Qué expone
Publica los eventos de seguridad que captura hacia el SIEM.
- `POST /events` (hacia el SIEM, formato común de evento)

## Qué consume
Nada obligatorio.

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.
