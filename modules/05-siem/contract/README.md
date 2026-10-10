# HU2 · Contrato de integración del SIEM (SEM-6)

Versión: `0.1.0-draft`. Estado: **propuesta revisable, pendiente de acuerdos y publicación**.

Este contrato permite a IDS, Honeypot y Escáner preparar el envío de eventos, y a SOAR y Dashboard preparar la consulta de alertas. Describe la interfaz; no implementa recepción, almacenamiento ni correlación.

## Ubicación y fuentes

Publicar estos archivos en `modules/05-siem/contract/` y los datos de ejemplo en `modules/05-siem/mocks/`. La carpeta se ha confirmado en la copia local del repositorio compartido. La rama debe pertenecer al equipo 5 e incluir `SEM-6`, siguiendo la convención existente.

Se han utilizado los tres JSON de `alertas_grupos/` y `mock_alertas_siem_soar.json`. Los originales se conservan sin cambios. El ejemplo IDS es simulado y está pendiente de confirmar con el grupo 2. Honeypot y Escáner son los ejemplos adaptados disponibles en el proyecto; no se presentan como datos reales de producción.

**Los recursos compartidos recibidos son placeholders.** `shared/event-schema.json` utiliza JSON Schema draft-07 y solo exige `type: object`: no fija claves ni tipos internos. `shared/auth-contract.md` enumera `/auth/login`, `/auth/validate` y `/secrets/{clave}`, con cuerpos de petición/respuesta pendientes, y los roles `admin`, `analista`, `servicio`. El esquema incluido en `openapi.json` es una propuesta más concreta y compatible con la condición actual de que un evento sea un objeto; eso no demuestra que exista un acuerdo definitivo. Antes de aprobar el contrato, acordar los campos y la autenticación con los equipos responsables. Esta propuesta no sustituye ni modifica los recursos compartidos.

## Direcciones y transporte

- Dirección local confirmada en el README del módulo: `http://localhost:8005`.
- Puerto interno que debe conservar el servicio: `80`.
- Peticiones y respuestas JSON: `Content-Type: application/json`.
- Autenticación: pendiente de completar el contrato de Identidad. Los roles disponibles son `admin`, `analista` y `servicio`, pero no se ha acordado su asignación a los endpoints del SIEM ni el formato de credencial. Su ausencia en este borrador no constituye autorización para acceder sin autenticar.

## Endpoints

| Método y ruta | Consumidores | Resultado |
| --- | --- | --- |
| `GET /health` | Infraestructura y CI | `200`, con `{"status":"ok","module":"05-siem"}`. Nombre confirmado en la configuración del placeholder. |
| `POST /events` | IDS, Honeypot y Escáner | Recibe **un objeto por petición**, valida y registra un evento. |
| `GET /alerts` | SOAR y Dashboard | `200`, con `{"alerts": [...]}`; sin alertas, `{"alerts": []}`. |
| `GET /alerts/{id}` | SOAR y Dashboard | `200`, con un objeto de alerta, o `404` si no existe. `id` es su `alert_id`. |

En esta versión no se proponen filtros, paginación ni orden garantizado. Los consumidores deben identificar las alertas mediante `alert_id`, nunca por su posición en la lista.

## Entrada: evento de seguridad

Todos los campos de la siguiente tabla son obligatorios. Se valida por nombre, sin depender del orden. Las claves superiores extra se rechazan en esta propuesta; `details` conserva los datos específicos del productor.

| Campo | Tipo | Regla propuesta |
| --- | --- | --- |
| `event_id` | string no vacío | Identificador único dentro de `source`, estable en los reintentos. No se exige UUID: el Honeypot utiliza un identificador `HP-…`. |
| `timestamp` | string | Fecha y hora válidas en UTC, terminadas en `Z`, por ejemplo `2026-09-22T18:30:15Z`. |
| `source` | string | `ids`, `honeypot` o `scanner`. Identifica al productor. |
| `event_type` | string no vacío | Ejemplos: `port_scan`, `fuerza_bruta`, `vulnerability_detected`. Catálogo compartido pendiente. |
| `severity` | string | `low`, `medium`, `high` o `critical`, pendiente de ratificar con el esquema compartido. |
| `title` | string no vacío | Resumen legible. |
| `description` | string no vacío | Explicación legible. |
| `details` | object | Datos específicos del productor; puede contener campos nulos. Su validación interna queda pendiente de los acuerdos por productor. |

El archivo original `eventos_unificados.json`, con valores `null`, es una plantilla y no una petición válida. No se aceptan lotes ni un contenedor `{"events": [...]}` en este endpoint.

### Respuestas de POST /events

Las siguientes respuestas y la política de duplicados son **decisiones propuestas**, pendientes de aceptación:

| Código | Significado |
| --- | --- |
| `201` | Evento nuevo registrado: `{"status":"accepted","source":"honeypot","event_id":"HP-981839239323"}`. |
| `200` | Reintento idéntico ya registrado: mismo formato, con `status: "duplicate"`. No crea otro evento. |
| `400` | El cuerpo no se puede interpretar como JSON. |
| `415` | Tipo de contenido distinto de `application/json`. |
| `422` | JSON válido que incumple el esquema. |
| `409` | Ya existe la misma pareja `(source, event_id)` con contenido distinto. |
| `500` | Error interno. |

La igualdad de contenido se comprueba sobre el JSON interpretado, ignorando el orden de las claves. La confirmación de un evento no garantiza que se haya generado una alerta: esa decisión corresponde a la correlación. El registro real del evento es trabajo de implementación, no una funcionalidad disponible por publicar este documento.

## Salida: alertas

Cada alerta incluye la cabecera del evento (`event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description`, `details`) y además:

| Campo | Tipo | Significado |
| --- | --- | --- |
| `alert_id` | string no vacío | Identificador estable asignado por SIEM; SOAR lo usa para evitar incidentes repetidos. |
| `source_ip` | string IPv4 o null | IP de origen observada. En IDS y Honeypot procede de `details.source_ip`. |
| `target_ip` | string IPv4 o null | Activo de destino. En IDS procede de `details.target_ip`; en Escáner, de `details.target.ip`. |

`timestamp` conserva el momento de detección del evento original. No es la fecha de creación o resolución del incidente. `details` conserva íntegramente los datos específicos del evento.

Para Escáner, `source_ip` es `null`: la IP escaneada es el activo y no se debe usar como IP atacante. En el ejemplo Honeypot, `target_ip` es `null` porque no se recibió ese dato. Este borrador cubre IPv4 y una alerta basada en un evento; el formato de alertas correlacionadas de varios eventos deberá acordarse antes de implementarlas.

## Errores

Formato propuesto común para errores de negocio y validación:

```json
{"error":{"code":"VALIDATION_ERROR","message":"El evento no cumple el esquema."}}
```

Códigos propuestos: `INVALID_JSON`, `UNSUPPORTED_MEDIA_TYPE`, `VALIDATION_ERROR`, `EVENT_CONFLICT`, `ALERT_NOT_FOUND`, `INTERNAL_ERROR`. Los errores de autenticación y autorización se incorporarán cuando Identidad complete `shared/auth-contract.md`.

## Ejemplos y mock

- `examples/grupo_2_ids_ejemplo_propuesto.json`: petición IDS simulada.
- `examples/grupo_3_honeypot.json`: petición Honeypot.
- `examples/grupo_4_scanner.json`: petición Escáner.
- `../mocks/alerts.json`: cuerpo fijo de respuesta para `GET /alerts`, con las tres alertas existentes.
- `openapi.json`: rutas, esquemas y ejemplos en OpenAPI 3.1.0. Referencia del estándar: <https://spec.openapis.org/oas/v3.1.0.html>.

`alerts.json` es un archivo estático. El placeholder actual implementa `/health` y devuelve un mensaje genérico en las demás rutas; publicar estos archivos no habilita los endpoints de la API ni pone en marcha un servidor mock.

## Cierre de la HU2

Lista provisional, a contrastar con los criterios reales de SEM-6:

- [ ] Incorporar los criterios de aceptación de la tarjeta.
- [x] Confirmar carpeta `modules/05-siem/`, nombre `05-siem` y puerto `8005` en la copia local del repositorio.
- [ ] Alinear la entrada con `shared/event-schema.json` y confirmar el ejemplo IDS.
- [ ] Incorporar la autenticación de `shared/auth-contract.md`.
- [ ] Acordar formatos y respuestas con productores, SOAR y Dashboard.
- [ ] Publicar el contrato y ejemplos en la rama del equipo con `SEM-6` en rama y commit.
- [ ] Abrir PR a `main`; comprobar `build-and-health` y `event-schema` en verde.
- [ ] Obtener la revisión cruzada: según el anillo indicado, el equipo 4 revisa el PR del equipo 5; verificar `CODEOWNERS`.
- [ ] Verificar los criterios con el PO delegado y completar el flujo de aprobación del repositorio.

No se acredita publicación, acuerdo entre grupos, ejecución de CI ni aprobación mientras no existan sus evidencias.
