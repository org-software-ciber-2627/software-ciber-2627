# Ejemplos simulados — Escáner / Dashboard

Estos archivos contienen cuerpos JSON para configurar el mock.
No proceden de escaneos reales.

| Archivo | Petición | HTTP |
|---|---|---|
| catalogo.json | GET /scans | 200 |
| informe_con_hallazgos.json | GET /scans/scan-001/report | 200 |
| informe_vacio.json | GET /scans/scan-002/report | 200 |
| pendiente.json | GET /scans/scan-003/report | 202 |
| en_curso.json | GET /scans/scan-003/report | 202 |
| error_404.json | GET /scans/no-existe/report | 404 |
| error_500_escaneo.json | GET /scans/scan-001/report, escenario de fallo | 500 |
| error_500_interno.json | GET /scans/scan-001/report, escenario de error interno | 500 |

## Configuración del mock

- Devolver Content-Type: application/json.
- Configurar el código HTTP indicado: no está incluido en el archivo JSON.
- El escenario inicial del catálogo contiene scan-001 y scan-002 completados,
  y scan-003 ejecutándose.
- pendiente.json y en_curso.json son escenarios alternativos del mismo trabajo.
  Para probar el pendiente, cambiar su status en el catálogo a pending.
- Para probar un escaneo fallido, cambiar su status en el catálogo a failed
  y devolver error_500_escaneo.json al consultar su informe.
- Para un catálogo vacío, devolver 200 con [].
- pending equivale a pendiente; running equivale a en_curso.
- Los errores del informe utilizan error.codigo y error.mensaje.
- No sustituir automáticamente una petición real fallida por estos ejemplos.
- Los identificadores scan-001, scan-002 y scan-003 son exclusivos del mock.
  En el servicio real se obtienen mediante GET /scans.

Contrato de referencia: [API del escáner](../README.md).