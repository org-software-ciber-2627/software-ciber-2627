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

## Prueba con la rama integrada (04/11/2026)

- SIEM: rama equipo-05-siem/SEM-21-recepcion-eventos-ids, commit 4cea894 (incluye SEM-22, SEM-30, SEM-70 y SEM-72).
- Honeypot: rama equipo-03-honeypot, commit 9bba185.
- Misma preparación que la prueba anterior (worktree del Honeypot y `.local/hu5/compose.yml` con `SIEM_URL=http://siem:80/events`), ejecutada desde un worktree de la rama integrada.

Resultados:

- Intento en /login con datos ficticios → evento HP-1, `event_type` credenciales_por_defecto, `severity` high.
- Honeypot: «Evento HP-1 enviado al SIEM con exito (HTTP 200)».
- SIEM: «Event processed and alert stored: event_id=HP-1, alert_id=SIEM-ALERT-df2c423e-2ffb-3655-a5ce-69bf46253aa6».
- `GET /alerts` y `GET /alerts/{alert_id}` devuelven la alerta con `source_ip`, `target_ip` null y los `details` completos del Honeypot.

Las capturas se aportan como evidencia en SEM-22.

## Contrato ratificado con G3 (04/11/2026)

G3 confirmó por Teams el contrato de POST /events (evidencia en SEM-22 y SEM-83).

| Respuesta | Significado | Comportamiento del Honeypot |
| --- | --- | --- |
| 200 | Evento aceptado. Un reenvío idéntico también da 200 sin duplicar la alerta | Marca el intento como enviado |
| 400 `INVALID_JSON` / `VALIDATION_ERROR` | Evento inválido | Registra el fallo y no reintenta |
| 415 `UNSUPPORTED_MEDIA_TYPE` | Content-Type distinto de application/json | Registra el fallo y no reintenta |
| 409 `EVENT_CONFLICT` | Mismo `source` y `event_id` con contenido distinto | Registra el fallo y no reintenta. Solo es posible si se borra el volumen honeypot-data con el SIEM en marcha |
| 413 `PAYLOAD_TOO_LARGE` | Cuerpo mayor de 64 KB | No alcanzable: los campos del Honeypot tienen como máximo 2000 caracteres |
| 507 `STORAGE_FULL` | El SIEM ya almacena 10 000 alertas | Registra el fallo; el intento queda con enviado=false |

Formato acordado: solo los 8 campos superiores (claves extra → 400), `event_id` de 1 a 128 caracteres (letras, dígitos y . _ : -), `timestamp` UTC terminado en Z, `source` honeypot, `severity` low/medium/high/critical, `event_type` intento_login, fuerza_bruta o credenciales_por_defecto, y `details` libre (source_ip, service, username, credential, command, ruta, navegador).

Las respuestas 409, 413 y 507 llegan a main con la integración de SEM-72.

## Alcance y limitaciones

- Las alertas se guardan en memoria: se pierden al reiniciar el SIEM.
- Pendiente de G3: añadir `SIEM_URL: http://siem:80/events` al servicio honeypot del docker-compose común. Mientras tanto, la prueba usa `.local/hu5/compose.yml`.