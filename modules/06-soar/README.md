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

## Mock local del SIEM (Sprint 1)

Simulación local del servicio SIEM (Equipo 5) para desacoplar el desarrollo del SOAR y cumplir los criterios del Sprint 1.

### Arranque rápido con Python
```bash
pip install -r requirements-mock.txt
uvicorn mock_siem_server:app --port 8000 --reload
