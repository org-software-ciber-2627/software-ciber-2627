# Contrato de API — Escáner / Dashboard

Historia: E4EDV-12  
Subtarea del contrato: E4EDV-48  
Estado: propuesta actualizada según los requisitos del Dashboard,
pendiente de confirmación final entre ambos equipos.

## 1. Objetivo

Permitir al Dashboard consultar las vulnerabilidades detectadas
en un escaneo mediante su identificador.

La consulta no inicia un escaneo ni envía eventos al SIEM.

## 2. Petición

Método: GET  
Ruta: /scans/{scan_id}/report

- `scan_id`: identificador del escaneo, de tipo string.
- La petición no lleva cuerpo.
- La URL base se configura según el entorno.
- Puerto de desarrollo del escáner: 8004.

Ejemplo local:

GET http://localhost:8004/scans/61869195-e638-477e-beee-3e466eab5212/report

Desde otro ordenador debe utilizarse una dirección del backend
accesible desde ese equipo, en lugar de localhost.

Autenticación: el endpoint actual no comprueba credenciales.
Cualquier cambio se acordará y documentará entre los equipos.

## 3. Informe disponible — 200 OK

Content-Type: application/json

La respuesta es una lista JSON directa de vulnerabilidades:

- No se utiliza un objeto contenedor como `{"findings": [...]}`.
- Se devuelve una lista incluso cuando solo hay un hallazgo.
- Todos los hallazgos corresponden al escaneo solicitado.

Ejemplo simulado:

```json
[
  {
    "event_id": "b52ee782-265f-4ec7-a719-484460628ef9",
    "timestamp": "2026-11-03T10:30:00Z",
    "source": "scanner",
    "event_type": "vulnerability_detected",
    "severity": "medium",
    "title": "Posible vulnerabilidad detectada",
    "description": "Un script NSE ha señalado un posible problema de seguridad.",
    "details": {
      "target": {
        "ip": "192.0.2.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http"
      },
      "scan_id": "61869195-e638-477e-beee-3e466eab5212",
      "tool": "nmap",
      "profile": "vuln",
      "script_id": "script-de-prueba",
      "evidence": "Evidencia simulada para validar el contrato.",
      "cve": null,
      "cvss": null
    }
  }
]
```

### Campos del hallazgo

Todas las claves de las tablas están presentes.
Los campos que admiten `null` se indican expresamente.

| Campo | Tipo | Descripción |
|---|---|---|
| event_id | string | Identificador original del evento; no cambia entre consultas. |
| timestamp | string | Fecha y hora del evento en UTC ISO 8601, terminada en Z. |
| source | string | Valor fijo: scanner. |
| event_type | string | Valor fijo en este informe: vulnerability_detected. |
| severity | string | low, medium, high o critical. |
| title | string | Título del hallazgo. |
| description | string | Descripción del hallazgo. |
| details | object | Información adicional del hallazgo. |

### Campos de details

| Campo | Tipo | Descripción |
|---|---|---|
| target | object | Objetivo al que corresponde el hallazgo. |
| scan_id | string | Identificador del escaneo solicitado. |
| tool | string | Herramienta utilizada; actualmente nmap. |
| profile | string | Perfil del escaneo: quick, web o vuln. |
| script_id | string o null | Identificador del script NSE, si está disponible. |
| evidence | string o null | Evidencia del hallazgo, si está disponible. |
| cve | string o null | Identificador CVE, si existe. |
| cvss | number o null | Puntuación CVSS entre 0 y 10, si existe. |

### Campos de details.target

| Campo | Tipo | Descripción |
|---|---|---|
| ip | string | Dirección IP del objetivo. |
| port | integer o null | Puerto al que corresponde el hallazgo. |
| protocol | string o null | Protocolo de transporte, por ejemplo tcp. |
| service | string o null | Servicio identificado, si está disponible. |

## 4. Selección y adaptación de eventos

El informe incluye únicamente los eventos internos de tipo:

- vulnerability_detected
- cve_detected

Ambos se presentan al Dashboard con:

```json
{
  "event_type": "vulnerability_detected"
}
```

Cuando existe una referencia CVE, se conserva en `details.cve`.

Se excluyen los eventos informativos:

- port_open
- service_detected

La adaptación se realiza sobre copias. No modifica los eventos
originales utilizados por el SIEM.

Se conservan `event_id`, `timestamp` y el resto de los campos.
Por tanto, el mismo evento puede tener un `event_type` normalizado
en el informe del Dashboard y su tipo original en el SIEM.

La respuesta no garantiza un orden concreto de los hallazgos.

## 5. Escaneo terminado sin vulnerabilidades — 200 OK

```json
[]
```

Significa que el escaneo ha terminado y no contiene eventos de
vulnerabilidad incluidos en este informe.

Puede haber detectado puertos abiertos o servicios y devolver igualmente
una lista vacía, porque esos eventos informativos se excluyen.

Una lista vacía no demuestra que el objetivo esté libre de vulnerabilidades:
solo indica que este escaneo no produjo hallazgos de los tipos incluidos.

## 6. Escaneo pendiente o en curso — 202 Accepted

```json
{
  "scan_id": "61869195-e638-477e-beee-3e466eab5212",
  "estado": "en_curso",
  "mensaje": "El informe todavía no está disponible"
}
```

Campos:

- `scan_id`: string con el identificador solicitado.
- `estado`: pendiente o en_curso.
- `mensaje`: string explicativo.

El Dashboard debe mostrar el estado y permitir volver a consultar.
No debe interpretar esta respuesta como un informe terminado sin hallazgos.

## 7. Escaneo inexistente — 404 Not Found

```json
{
  "error": {
    "codigo": "SCAN_NOT_FOUND",
    "mensaje": "No existe un escaneo con ese identificador"
  }
}
```

Se devuelve cuando no existe un trabajo con el identificador solicitado.

## 8. Escaneo fallido — 500 Internal Server Error

```json
{
  "error": {
    "codigo": "SCAN_FAILED",
    "mensaje": "El escaneo ha fallado y no hay un informe disponible"
  }
}
```

Se devuelve cuando el trabajo de escaneo está marcado como fallido.

Consultar de nuevo el informe no reinicia el escaneo.
Para repetir la ejecución debe crearse un nuevo trabajo.

## 9. Error interno — 500 Internal Server Error

```json
{
  "error": {
    "codigo": "INTERNAL_ERROR",
    "mensaje": "No se pudo recuperar el informe"
  }
}
```

Se devuelve si el informe almacenado no tiene la estructura esperada
o se produce una excepción inesperada al atender la consulta.

Los detalles técnicos se registran en el servidor.
No se incluyen trazas ni errores internos en la respuesta al Dashboard.

## 10. Comportamiento esperado del Dashboard

| Respuesta o situación | Comportamiento esperado |
|---|---|
| 200 con hallazgos | Mostrar las vulnerabilidades del escaneo. |
| 200 con [] | Mostrar que el escaneo terminó sin vulnerabilidades detectadas. |
| 202 | Mostrar pendiente o en curso y permitir volver a consultar. |
| 404 | Mostrar que el escaneo no existe. |
| 500 con SCAN_FAILED | Mostrar que el escaneo falló. |
| 500 con INTERNAL_ERROR | Mostrar que no se pudo recuperar el informe y permitir reintentar la consulta. |
| Sin conexión o timeout | Mostrar un error de comunicación. |
| JSON inválido o con formato inesperado | Mostrar un error de procesamiento de la respuesta. |

El cliente debe comprobar el código HTTP antes de tratar el cuerpo como
una lista de hallazgos. No debe depender del texto exacto de `mensaje`
para identificar un error: debe utilizar `error.codigo`.

## 11. Datos simulados

Se permite utilizar datos simulados para pruebas y desarrollo.

- Deben respetar este contrato.
- Su uso debe estar identificado y activarse explícitamente.
- No se sustituye automáticamente una petición real fallida por datos ficticios.
- Un archivo sin contenido no equivale a la lista JSON válida `[]`.
- Los ejemplos deben cubrir resultados, lista vacía, estado en curso y errores.

Los equipos acordarán y documentarán la ubicación de los archivos de ejemplo
y el punto concreto donde el Dashboard los lee.

## 12. Limitaciones actuales

- Los trabajos y sus resultados se guardan en memoria.
- Al reiniciar el backend, los identificadores anteriores dejan de existir.
- Este endpoint no proporciona un catálogo de escaneos.
- Actualmente, el identificador se obtiene al crear un escaneo mediante
  POST /scan. Para pruebas puede facilitarlo el equipo del escáner.
- La consulta del informe no vuelve a ejecutar Nmap.
- La conexión real desde la interfaz del Dashboard está prevista para
  el Sprint 3, según la planificación comunicada por su equipo.



