# Contrato de API — Escáner / Dashboard

Historia: E4EDV-12 · Subtarea: E4EDV-48  
Estado: aceptado por el Dashboard según confirmación comunicada.  
Integración real de la interfaz: Sprint 3.

La aceptación del contrato no implica que el PR esté fusionado
ni que la integración real esté validada.

## 1. Conexión y acuerdos

- Acceso local al escáner: `http://localhost:8004`.
- Entre servicios Docker: `http://escaner:80`.
- El Dashboard utilizará su proxy nginx `/api/escaner/` hacia
  `http://escaner:80/`. Esta configuración no requiere CORS en el escáner.
- Las peticiones GET no llevan body y las respuestas son JSON.
- Actualmente el escáner no comprueba autenticación.

Se mantienen los nombres acordados:

| Estado en el catálogo | Estado en la respuesta 202 |
|---|---|
| pending | pendiente |
| running | en_curso |

Los errores del informe utilizan `error.codigo` y `error.mensaje`.
Cualquier cambio de estos formatos se acordará previamente entre equipos.

## 2. Catálogo de escaneos

`GET /scans`

Devuelve `200 OK` con una lista ordenada por fecha de creación,
del más reciente al más antiguo:

```json
[
  {
    "scan_id": "scan-001",
    "created_at": "2026-11-06T10:30:00Z",
    "target": "192.0.2.10",
    "profile": "web",
    "status": "completed"
  }
]
```

- `created_at`: fecha de creación en UTC ISO 8601, terminada en `Z`.
  Si falta en un trabajo antiguo, devuelve `null` y se coloca al final.
- `profile`: `quick`, `web` o `vuln`.
- `status`: `pending`, `running`, `completed` o `failed`.
- Sin escaneos: `200 OK` con `[]`.
- No incluye eventos ni tiene paginación.

El Dashboard obtiene aquí el `scan_id` y consulta su informe.
Los identificadores de los ejemplos son simulados; no deben utilizarse
como identificadores fijos contra el servicio real.

## 3. Informe de vulnerabilidades

`GET /scans/{scan_id}/report`

La consulta no inicia ni repite el escaneo.

### Informe disponible — 200 OK

Devuelve una lista directa, sin contenedor `events` ni `findings`.

```json
[
  {
    "event_id": "b52ee782-265f-4ec7-a719-484460628ef9",
    "timestamp": "2026-11-06T10:31:00Z",
    "source": "scanner",
    "event_type": "vulnerability_detected",
    "severity": "medium",
    "title": "Posible vulnerabilidad detectada",
    "description": "Hallazgo simulado para probar la integración.",
    "details": {
      "target": {
        "ip": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http"
      },
      "scan_id": "scan-001",
      "tool": "nmap",
      "profile": "web",
      "script_id": "script-de-prueba",
      "evidence": "Evidencia simulada.",
      "cve": null,
      "cvss": null
    }
  }
]
```

Reglas:

- Todas las claves del ejemplo están presentes.
- `source` siempre es `scanner`.
- `event_type` siempre es `vulnerability_detected` en este informe.
- `severity`: `low`, `medium`, `high` o `critical`.
- `timestamp`: fecha del evento en UTC ISO 8601 terminada en `Z`.
- `event_id` y `timestamp` se conservan entre consultas.
- `script_id`, `evidence` y `cve` son strings o `null`.
- `cvss` es un número entre 0 y 10, o `null`.
- `target.ip` es un string; `port` es un entero o `null`;
  `protocol` y `service` son strings o `null`.
- Todos los hallazgos pertenecen al escaneo solicitado.
- No se garantiza un orden concreto de los hallazgos.

Se incluyen los eventos internos `vulnerability_detected` y
`cve_detected`. Se adapta una copia para presentar ambos como
`vulnerability_detected`, conservando el CVE en `details.cve`.

Los originales utilizados para publicar al SIEM no se modifican.
Se excluyen los eventos informativos `port_open` y `service_detected`.

### Escaneo terminado sin vulnerabilidades — 200 OK

```json
[]
```

Puede haber detectado puertos o servicios y devolver igualmente `[]`.
Esto no demuestra que el objetivo esté libre de vulnerabilidades.

### Pendiente o en curso — 202 Accepted

```json
{
  "scan_id": "scan-001",
  "estado": "en_curso",
  "mensaje": "El informe todavía no está disponible"
}
```

`estado` puede ser `pendiente` o `en_curso`.
El Dashboard debe mostrarlo y permitir consultar de nuevo.

### Errores del informe

| HTTP | error.codigo | Significado |
|---|---|---|
| 404 | SCAN_NOT_FOUND | El escaneo no existe. |
| 500 | SCAN_FAILED | El escaneo ha fallado. |
| 500 | INTERNAL_ERROR | No se pudo recuperar el informe. |

Formato:

```json
{
  "error": {
    "codigo": "SCAN_NOT_FOUND",
    "mensaje": "No existe un escaneo con ese identificador"
  }
}
```

El Dashboard debe comprobar el código HTTP y `error.codigo`.
No debe depender del texto exacto de `mensaje`.

Un error, un timeout o una respuesta 202 no equivalen a un informe vacío.

## 4. Salud

`GET /health`

Devuelve `200 OK`:

```json
{
  "status": "ok",
  "module": "04-escaner"
}
```

Confirma que la API responde, no la disponibilidad de Nmap o del SIEM
ni la entrega de eventos.

## 5. Rutas conservadas por compatibilidad

- `GET /events`: alias de `/scans`; devuelve el mismo listado ordenado.
  El Dashboard utilizará `/scans`.
- `GET /scan/{scan_id}`: devuelve el trabajo con sus eventos originales
  en `events`, incluidos los informativos. Si no existe, devuelve 404
  con `{"error": "scan no encontrado"}`.

El `GET /events` del escáner es independiente del `POST /events` del SIEM.

## 6. Comparación de escaneos

`GET /diff?base={id_base}&target={id_target}`

Ambos parámetros son obligatorios e identifican escaneos.

Respuesta `200 OK`:

```json
{
  "base_scan_id": "scan-base",
  "target_scan_id": "scan-target",
  "diff": {
    "new": [],
    "fixed": [],
    "unchanged": []
  }
}
```

Las listas contienen eventos originales, incluidos los informativos:

- `new`: aparecen solo en el segundo escaneo.
- `fixed`: aparecen solo en el primero; no demuestra una corrección.
- `unchanged`: coinciden por IP, puerto y título.

La comparación utiliza `details.target.ip`, `details.target.port`
y `title`; no compara todos los campos del evento.

Respuestas de error:

- 400: faltan parámetros.
- 404: algún escaneo no existe.
- 409: algún escaneo está pendiente, ejecutándose o fallido.
- 500: estado desconocido, si no se ha detectado antes un estado
  que produzca 409.

Los errores de esta ruta utilizan `{"error": "mensaje"}`.
Solo se comparan dos escaneos en estado `completed`.

## 7. Ejemplos y simulación

Los cuerpos de prueba y sus códigos HTTP están en
[los ejemplos del Dashboard](dashboard/README.md).

Incluyen catálogo, hallazgos, lista vacía, estados pendientes/en curso
y errores. El mock debe configurar el código HTTP correspondiente;
este no está incluido en el archivo JSON.

El uso de datos simulados debe ser explícito.
No se sustituye automáticamente una petición real fallida por un mock.

El Dashboard construirá su mock a partir de estos ejemplos.
La integración real mediante su proxy queda para el Sprint 3.

## 8. Limitaciones

- Los trabajos se guardan en memoria y se pierden al reiniciar.
- Consultar el catálogo o el informe no lanza escaneos ni publica al SIEM.
- Un informe disponible no confirma que sus eventos hayan sido
  almacenados por el SIEM.
- La aceptación de este contrato y la validación de la integración
  son hitos distintos.


