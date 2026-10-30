# Contrato de API — Escáner / Dashboard

Historia: E4EDV-48
Estado: propuesta pendiente de revisión por el equipo del Dashboard.

## Objetivo

Permitir al Dashboard consultar los hallazgos de un escaneo.

## Petición

GET /scans/{scan_id}/report

- scan_id: identificador del escaneo.
- La petición no lleva cuerpo.
- Esta consulta no inicia un nuevo escaneo.

Ejemplo:

GET /scans/scan-001/report

## Respuesta correcta — 200 OK

Content-Type: application/json

La respuesta es una lista de hallazgos.
Cada hallazgo utiliza el formato acordado con el SIEM.

```json
[
  {
    "event_id": "b52ee782-265f-4ec7-a719-484460628ef9",
    "timestamp": "2026-09-29T10:30:00Z",
    "source": "scanner",
    "event_type": "vulnerability_detected",
    "severity": "medium",
    "title": "Cabecera de seguridad ausente",
    "description": "El servicio HTTP no devuelve X-Content-Type-Options.",
    "details": {
      "target": {
        "ip": "192.168.56.10",
        "port": 80,
        "protocol": "tcp",
        "service": "http"
      },
      "scan_id": "scan-001",
      "tool": "nmap",
      "profile": "web",
      "script_id": "http-headers",
      "evidence": "X-Content-Type-Options no aparece en las cabeceras recibidas.",
      "cve": null,
      "cvss": null
    }
  }
]
```

## Reglas de la respuesta

- Se devuelve una lista incluso si solo hay un hallazgo.
- Todos los hallazgos corresponden al `scan_id` solicitado.
- event_id se conserva entre consultas y coincide con el enviado al SIEM.
- timestamp se expresa en UTC con formato ISO 8601.
- cve y cvss pueden ser null.
- Un escaneo terminado sin hallazgos devuelve `200 OK` con `[]`.

## Respuestas alternativas propuestas

### Escaneo pendiente o en curso — 202 Accepted

```json
{
  "scan_id": "scan-001",
  "estado": "en_curso",
  "mensaje": "El informe todavía no está disponible"
}
```

estado puede ser pendiente o en_curso.

### Escaneo inexistente — 404 Not Found

```json
{
  "error": {
    "codigo": "SCAN_NOT_FOUND",
    "mensaje": "No existe un escaneo con ese identificador"
  }
}
```

### Error al recuperar el informe — 500 Internal Server Error

```json
{
  "error": {
    "codigo": "INTERNAL_ERROR",
    "mensaje": "No se pudo recuperar el informe"
  }
}
```

Un error no debe interpretarse como un escaneo sin hallazgos.

## Datos simulados

Los ejemplos de prueba tendrán el mismo formato que los datos reales.
Su uso será explícito y no sustituirá automáticamente una respuesta
real fallida.

## Pendiente de acordar
