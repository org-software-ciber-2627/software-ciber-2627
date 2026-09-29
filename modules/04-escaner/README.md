# Módulo 4 · Escáner de vulnerabilidades

- **Equipo propietario:** `equipo-04-escaner`
- **Puerto:** `8004`

## Qué expone
Publica los hallazgos de sus escaneos hacia el SIEM. Opcionalmente expone una API propia de histórico de escaneos.
- `POST /events` (hacia el SIEM, formato común de evento)
- API de histórico de escaneos (opcional, para que el Dashboard la use directamente)

## Qué consume
Nada obligatorio.

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.
