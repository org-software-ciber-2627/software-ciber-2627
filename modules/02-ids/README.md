# Módulo 2 · IDS/NIDS ligero

- **Equipo propietario:** `equipo-02-ids`
- **Puerto:** `8002`

## Qué expone
Publica los eventos de seguridad que detecta hacia el SIEM.
- `POST /events` (hacia el SIEM, formato común de evento)

## Qué consume
Nada obligatorio (opcionalmente puede validar sesión de su panel de administración contra Identidad).

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.
