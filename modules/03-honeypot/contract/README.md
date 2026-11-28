# Contrato de Eventos - Integración Honeypot con SIEM

Este documento define la estructura estandarizada de eventos generados por el Honeypot (Grupo 3) conforme al esquema común acordado con el SIEM (Grupo 5).

## Especificación del Formato Común

El cuerpo del evento contiene **exactamente 8 campos obligatorios en la raíz**:

| Campo | Tipo | Requerido | Descripción | Ejemplo |
| :--- | :--- | :---: | :--- | :--- |
| `event_id` | String | Sí | Identificador idempotente prefijado con el módulo y el ID del registro. | `"HP-101"` |
| `timestamp` | String | Sí | Fecha y hora en formato UTC ISO-8601 (`YYYY-MM-DDTHH:mm:ssZ`). | `"2026-10-12T14:30:00Z"` |
| `source` | String | Sí | Identificador del sistema emisor. Fijo para este módulo. | `"honeypot"` |
| `event_type` | String | Sí | Tipología del evento: `intento_login` (intento sin clasificar), `fuerza_bruta`, `credenciales_por_defecto`, `escaneo` o `peticiones_rechazadas`. Si es a la vez fuerza bruta y credenciales por defecto, se envía `fuerza_bruta`. | `"intento_login"` |
| `severity` | String | Sí | Severidad normalizada: `info`, `low`, `medium`, `high`, `critical`. | `"medium"` |
| `title` | String | Sí | Resumen conciso del evento. | `"Intento de acceso en el login falso"` |
| `description`| String | Sí | Descripción contextual del atacante y credenciales. | `"Intento desde 192.168.1.45 con el usuario admin"` |
| `details` | Object | Sí | Mapa de metadatos detallados específicos del honeypot. | Ver tabla inferior |

### Estructura del objeto `details`

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `source_ip` | String | Dirección IP origen del intento de acceso. |
| `service` | String | Servicio atacado (`honeypot-web`, `ftp` o `honeypot-ssh`). |
| `username` | String | Nombre de usuario empleado (o `null` si no aplica). |
| `credential` | String | Contraseña o credencial intentada (o `null` si no aplica). |
| `command` | String | Comando ejecutado en caso de interactividad (o `null`). |
| `ruta` | String | Endpoint o ruta web invocada (ej. `/login`). |
| `navegador` | String | User-Agent de la cabecera HTTP. |

### Evento resumen `peticiones_rechazadas`

Resumen de las peticiones que el limitador ha rechazado, con una fila por IP, servicio y minuto. Se envía al acabar cada minuto, solo para los minutos con rechazos.

* `event_id`: `HP-R-<id>`, con el identificador del resumen (no es el de un intento de acceso).
* `timestamp`: inicio del minuto resumido.
* `severity`: `info`.
* `details` lleva campos distintos a los de un intento de acceso:

| Campo | Tipo | Descripción |
| :--- | :--- | :--- |
| `source_ip` | String | Dirección IP cuyas peticiones se rechazaron. |
| `service` | String | Servicio en el que se rechazaron. |
| `minuto` | String | Inicio del minuto resumido, en UTC ISO-8601. |
| `rechazos` | Integer | Número de peticiones rechazadas en ese minuto. |

---

## Respuestas HTTP esperadas (Mock / SIEM)

* **`201 Created`**: Evento recibido y validado con éxito.
* **`200 OK`**: Evento procesado correctamente (aceptado en envíos idempotentes/reintentos).
* **`422 Unprocessable Entity`**: Faltan campos obligatorios en la raíz del evento.
* **`400 Bad Request`**: Carga útil no válida o JSON mal formado.