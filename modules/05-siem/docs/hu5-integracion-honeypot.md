# HU5 · Integración del Honeypot con el SIEM

Historia: SEM-22 — Recibir eventos reales del Honeypot.  
Fecha de ejecución: 26/10/2026.

## Objetivo

Comprobar que los eventos generados por el Honeypot del grupo 3 llegan al endpoint POST /events del SIEM del grupo 5.

## Entorno y configuración

- SIEM: rama equipo-05-siem/SEM-22-honeypot.
- Honeypot: rama equipo-03-honeypot, commit 98c8821, preparada en un worktree independiente.
- Ejecución mediante Docker Compose.
- SIEM accesible desde el Mac en http://localhost:8005.
- Honeypot accesible desde el Mac en http://localhost:8003.
- Variable del Honeypot: SIEM_URL=http://siem:80/events.

Para reproducir la prueba desde la raíz del repositorio, preparar el worktree:

```bash
git fetch origin
git worktree add --detach ../software-ciber-honeypot origin/equipo-03-honeypot
```

Si ya existe, reutilizarlo. Para repetir exactamente esta prueba, utilizar la versión 98c8821 del Honeypot.

Crear `.local/hu5/compose.yml` con:

```yaml
services:
  honeypot:
    build:
      context: ../software-ciber-honeypot/modules/03-honeypot
    environment:
      SIEM_URL: http://siem:80/events
```

Arrancar ambos servicios:

```bash
docker compose -f docker-compose.yml -f .local/hu5/compose.yml up --build -d siem honeypot
```

Enviar un intento con datos ficticios mediante el formulario /login y consultar:

```bash
docker compose logs -f siem honeypot
```

## Resultados observados

Se generaron los eventos HP-1 y HP-2 mediante intentos en el Honeypot.

Para ambos identificadores:

- El SIEM registró la recepción con source=honeypot.
- El Honeypot confirmó el envío con HTTP 200.
- El identificador coincidió en los registros de ambos servicios.

Las capturas y los registros de ejecución se aportan como evidencia en Jira.

## Prueba automática añadida

acceptsCurrentHoneypotPayloadAndPreservesDetails utiliza el ejemplo grupo_3_honeypot_actual.json y comprueba:

- Conservación completa del evento al convertirlo al modelo y volver a JSON.
- Conservación de ruta, navegador y command=null.
- Recepción mediante POST /events con HTTP 200.
- Coincidencia del event_id en el acuse.

Ejecución desde la raíz del repositorio:

```bash
docker run --rm -v "$PWD/modules/05-siem:/workspace" -w /workspace maven:3.9-eclipse-temurin-21 sh ./mvnw -B test
```

Resultado: 8 pruebas ejecutadas, 0 fallos, 0 errores y 0 omitidas.

## Alcance y limitaciones

La prueba acredita el envío desde el Honeypot real y la recepción por el SIEM. La versión probada valida y registra los eventos en el log; no acredita almacenamiento en base de datos, deduplicación ni generación de alertas.

La persistencia se coordina con HU8. Sigue pendiente ratificar con G3 la documentación de respuestas HTTP: esta versión devuelve 200 para eventos válidos y 400 para eventos inválidos.