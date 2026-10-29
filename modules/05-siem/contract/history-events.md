# Consulta del histórico de eventos · HU10 / SEM-27

## Estado y alcance

Este documento especifica el diseño de `GET /events` para HU10.

HU10 consulta los eventos realmente almacenados en PostgreSQL mediante el repositorio de HU8. No crea otra base de datos ni modifica el formato de ingesta. `POST /events` conserva su función de recepción; `GET /events` añade la consulta sobre la misma ruta.

Quedan fuera los filtros de HU11, búsqueda textual, detalle individual de eventos, cambios en alertas, nuevos productores y protección de endpoints mediante IAM. Los cambios propios de HU10 se limitan a `modules/05-siem`.

## Petición

```http
GET /events?limit=100&offset=0
Accept: application/json
```

La petición no necesita cuerpo. La respuesta utiliza `Content-Type: application/json`.

| Parámetro | Tipo | Predeterminado | Regla |
| --- | --- | --- | --- |
| `limit` | Entero | `100` | Entre `1` y `500`, ambos incluidos |
| `offset` | Entero | `0` | Entre `0` y `9223372036854775807 - limit`; número de eventos que se omiten al inicio del resultado ordenado |

Omitir ambos parámetros equivale a `GET /events?limit=100&offset=0`. Un parámetro presente pero vacío, no entero o fuera de su rango válido produce 400; no se sustituye silenciosamente por el valor predeterminado. Los valores que no puedan representarse de forma segura en la implementación se rechazan con 400, sin truncamiento ni desbordamiento aritmético. Se aceptan únicamente entre 1 y 19 dígitos ASCII, sin signos, espacios, decimales ni exponentes. El valor debe caber en un entero Java `long`; además, `offset + limit` no puede superar `9223372036854775807`. Los parámetros duplicados o desconocidos producen 400. La sincronización de estos límites con OpenAPI corresponde a SEM-100.

No se incorporan filtros por origen, severidad, tipo de evento o fechas en HU10.

## Orden de los resultados

La consulta utiliza este orden fijo:

```sql
ORDER BY occurred_at DESC, source ASC, event_id ASC
```

1. Primero aparecen los eventos con mayor `occurred_at`, que representa la fecha del evento, no su fecha de recepción.
2. Cuando coincide esa fecha, `source` y `event_id` desempatan según la ordenación de PostgreSQL configurada para esas columnas.
3. La clave primaria `(source, event_id)` identifica cada evento y completa un orden determinista para un conjunto de filas sin cambios. Dos productores pueden utilizar el mismo `event_id` sin que se trate del mismo evento.

`occurred_at` utiliza la precisión temporal de PostgreSQL. El texto original puede conservar más precisión; por tanto, dos timestamps originales distintos pueden empatar en `occurred_at` y ordenarse por la clave compuesta. No se promete orden completo por nanosegundos originales.

## Respuesta correcta

HTTP 200 devuelve un objeto con tres propiedades:

| Campo | Tipo | Significado |
| --- | --- | --- |
| `events` | Array de eventos | Página de eventos persistidos, con un máximo de `limit` elementos |
| `next_offset` | Entero o `null` | Desplazamiento que permite solicitar otra página, o `null` si la consulta no observa más filas |
| `next` | String o `null` | Referencia URI relativa al origen para solicitar la siguiente página conservando `limit`; `null` al finalizar |

Cada evento conserva los ocho campos del modelo existente: `event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description` y `details`. No se exponen columnas SQL adicionales ni se añaden campos públicos al evento.

Ejemplo de una página sin continuación:

```json
{
  "events": [
    {
      "event_id": "SCAN-EXAMPLE-001",
      "timestamp": "2026-10-29T10:00:00.123456789Z",
      "source": "scanner",
      "event_type": "vulnerability_detected",
      "severity": "medium",
      "title": "Example finding",
      "description": "Example event for history verification",
      "details": {
        "scan_id": "SCAN-EXAMPLE",
        "cve": null,
        "evidence": ["Example evidence"],
        "verified": false
      }
    }
  ],
  "next_offset": null,
  "next": null
}
```

Se reutiliza el mapeo de lectura de HU8:

- `timestamp` conserva `original_timestamp` cuando está disponible. Para filas anteriores a esa columna o con valor nulo, se obtiene de `occurred_at` y se representa en UTC, como hace el repositorio existente.
- `details` conserva su estructura y valores: objetos, listas, booleanos, nulos y números, evitando introducir conversiones intermedias a `double` que pierdan precisión decimal.
- JSONB no conserva necesariamente el orden de las claves ni la escritura numérica original. La fidelidad se refiere a los valores y la estructura, no a igualdad byte a byte con el JSON enviado.

## Navegación y resultados vacíos

La implementación consulta como máximo `limit + 1` filas para detectar continuación, devuelve solo las primeras `limit` y no necesita contar toda la tabla.

- Si se observa una fila adicional, `next_offset` será `offset + limit`.
- Si no existe una fila adicional, `next_offset` será `null`.
- Se valida la suma sin permitir desbordamientos. Un desplazamiento que no pueda procesarse con seguridad se rechaza con 400.
- El cliente puede seguir `next` directamente, resolviéndolo contra el origen de la API, o conservar el `limit` de su consulta al utilizar `next_offset`.
- `next` y `next_offset` son nulos cuando no hay continuación. La existencia del enlace no garantiza que los datos no cambien antes de solicitarlo.

Por ejemplo, con `limit=2`, `offset=0` y al menos tres filas disponibles, la respuesta contiene dos eventos, `next_offset: 2` y `next: "/events?limit=2&offset=2"`. El consumidor puede solicitar directamente ese enlace.

Una base vacía o un desplazamiento posterior al último resultado devuelve HTTP 200:

```json
{
  "events": [],
  "next_offset": null,
  "next": null
}
```

No se devuelve 404 por una colección vacía ni se incluye un recuento total.

### Construcción del enlace de continuación

El controlador construye `next` con el contexto Servlet de la aplicación, la ruta fija `/events` y los valores numéricos ya validados de `limit` y `next_offset`. No copia parámetros desconocidos ni construye dominios a partir de `Host` o `X-Forwarded-Host`.

Sin contexto Servlet, el enlace tiene la forma `/events?limit=100&offset=100`; con contexto `/siem`, es `/siem/events?limit=100&offset=100`. Es una referencia relativa al origen: no incluye esquema ni dominio. Un proxy que añada otro prefijo público requiere configurar y revisar explícitamente ese despliegue; no se infiere un prefijo externo de cabeceras arbitrarias.

Se conserva `next_offset` para consumidores que prefieran construir sus peticiones. Añadir `next` no cambia el SQL, el tamaño de página ni el almacenamiento.

### Límite de consistencia y coste

La navegación por desplazamiento no conserva una instantánea entre peticiones. Nuevas inserciones o cambios del conjunto de filas pueden desplazar los resultados y producir repeticiones u omisiones durante el recorrido. `next_offset` describe la continuación observada por esa consulta, no una garantía sobre peticiones futuras.

El límite acota las filas devueltas, pero no garantiza un coste constante: los desplazamientos grandes pueden resultar más caros. Una navegación estable mediante cursor o una instantánea queda fuera de este diseño y requeriría una decisión posterior.

## Errores

Se conserva el formato común `error.code` y `error.message`. Los mensajes del servidor se escriben en inglés y no incluyen credenciales, SQL, detalles internos de conexión ni el contenido de los eventos.

| Situación | HTTP | Código |
| --- | --- | --- |
| Consulta correcta, con o sin resultados | `200` | No aplica |
| Parámetros vacíos, no enteros, fuera de rango o no representables con seguridad | `400` | `VALIDATION_ERROR` |
| Perfil de persistencia desactivado, almacenamiento inaccesible o timeout de consulta | `503` | `STORAGE_UNAVAILABLE` |
| Defecto inesperado de consulta o ejecución | `500` | `INTERNAL_ERROR` |

Ejemplo de parámetro inválido:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid history query parameters"
  }
}
```

Ejemplo de almacenamiento no disponible:

```json
{
  "error": {
    "code": "STORAGE_UNAVAILABLE",
    "message": "Event storage is temporarily unavailable"
  }
}
```

Una consulta fallida no debe convertirse en una lista vacía ni devolver resultados parciales como éxito. Esta tabla no convierte cualquier defecto de programación en un 503: ese código corresponde a indisponibilidad de almacenamiento.

Con el perfil `persistence` activo, HU8 requiere PostgreSQL disponible al iniciar. Si la configuración o la conexión impiden arrancar la aplicación, no existe una respuesta HTTP; ese fallo se diagnostica durante el arranque.

## Seguridad y responsabilidad del módulo

`limit` y `offset` son parámetros de navegación; no se introducen secretos o credenciales en la URL. GET no proporciona autenticación, autorización ni cifrado. El endpoint implementado hereda la ausencia de protección IAM de la base revisada; no se declara protegido ni se implementan HU18/HU19 dentro de HU10.

La consulta devuelve los atributos persistidos, que pueden contener información sensible de los productores. Los ejemplos y las pruebas utilizarán únicamente datos ficticios y saneados; no se registrarán cuerpos de eventos en los logs de consulta. No se aplica una redacción silenciosa que altere el contrato sin acuerdo previo.

Los desacuerdos de formato de otros módulos se coordinan con sus responsables. HU10 no modifica productores ni añade adaptadores específicos para ellos.

## Criterios de aceptación y verificación prevista

Los siguientes casos guían SEM-99. La verificación local del 29/10/2026 combina PostgreSQL real, HTTP y repositorios de prueba; el detalle de la evidencia se recoge al final. No todos los casos tienen una prueba específica sobre PostgreSQL real.

| Caso | Resultado exigido |
| --- | --- |
| Sin parámetros | Valores predeterminados y respuesta JSON con los tres campos definidos |
| Base vacía o desplazamiento más allá del final | 200, array vacío, `next_offset: null` y `next: null` |
| Un evento persistido mediante POST | Aparece en GET con sus ocho campos y mapeo fiel |
| Tres productores y un identificador compartido entre fuentes | Todos se recuperan sin confundir la identidad compuesta |
| Fechas distintas y fechas empatadas | Orden conforme a `occurred_at`, `source` y `event_id` |
| Número de filas igual, inferior o superior al límite | Tamaño de página y continuación correctos; seguir `next` conserva el límite y no pierde la fila adicional |
| Contexto Servlet y cabeceras de host reenviado | Enlace con el contexto correcto y sin dominios tomados de cabeceras arbitrarias |
| Límite mínimo/máximo y desplazamiento válido | Consulta acotada y coherente con sus parámetros |
| Valores vacíos, negativos, decimales, no numéricos o excesivos | 400, sin truncamientos ni desbordamientos |
| JSON anidado, nulos y decimales | Estructura y valores conservados al consultar |
| Fila sin `original_timestamp` | Recuperación compatible con el mapeo de HU8 |
| Evento rechazado o reenvío idéntico | El rechazado no aparece; el reenvío no añade otra fila |
| Persistencia desactivada o caída durante la consulta | 503, sin éxito aparente ni datos internos |
| Reinicio conservando almacenamiento | Los eventos siguen disponibles al consultar |

Las pruebas de integración utilizarán almacenamiento desechable y no borrarán volúmenes ni datos de trabajo. Se distinguirán pruebas propias, resultados declarados por JC y comprobaciones de CI. El comportamiento ante peticiones simultáneas respetará la limitación de navegación documentada.

## Implementación, seguridad y condiciones de cierre

- **SEM-97:** contrato preparado y actualizado con el diseño autorizado por Oliver. Pendiente de revisión del equipo/JC y aceptación del PO cuando corresponda; no se atribuyen acuerdos de terceros.
- **SEM-98:** implementación local completa de repositorio, servicio y controlador, verificada con PostgreSQL real. Cambios propios limitados a `modules/05-siem`; no se modifica el formato de ingesta ni se añade otra persistencia.
- **SEM-99:** se ha ejecutado la suite disponible y el recorrido de caída/recuperación. La matriz de aceptación y su evidencia deben revisarse como subtarea propia; no se declara cerrada automáticamente.
- **SEM-100:** pendiente sincronizar OpenAPI, documentación general y revisión/aceptación final de la historia.

`PostgresEventRepository.findPage` usa SQL fijo y enlaza `fetchLimit` y `offset` como parámetros JDBC; no concatena valores del cliente ni acepta ordenación arbitraria. El controlador rechaza entradas malformadas antes de consultar el repositorio. Las respuestas correctas y los errores gestionados por el histórico incluyen `Cache-Control: no-store`; sus errores no exponen SQL, credenciales ni cuerpos de eventos.

La lectura del histórico tiene un timeout JDBC de cinco segundos y comparte el pool de HU8. Se ha verificado que se configura en el statement mediante una prueba JDBC; no se ha provocado un bloqueo real para medir su cancelación en PostgreSQL. No constituye un límite global de duración de la petición. La limitación por filas no limita el tamaño en bytes de los eventos ni elimina el coste de desplazamientos grandes.

El enlace `next` conserva `limit` y el contexto Servlet, y es nulo junto con `next_offset` al terminar. No modifica SQL ni almacenamiento. La API sigue sin IAM; esta implementación no acredita integración real con los productores.

Este contrato no actualiza por sí mismo `contract/openapi.json`. La ingesta persistente se describe en [sem65-ingestion-proposal.md](sem65-ingestion-proposal.md). La ejecución utiliza el perfil y las variables de la [guía de persistencia](../docs/sem67-persistence-guide.md).

## Verificación local · 29/10/2026

Comando ejecutado desde `modules/05-siem`, con Java 21, Docker Desktop y PostgreSQL `17-alpine`:

```zsh
python3 -B scripts/test-storage.py --offline
```

Resultados propios observados:

- **56 pruebas Java ejecutadas**, cero fallos, errores u omisiones; `BUILD SUCCESS`. Incluyen 17 casos de `PersistentEventHttpTests` y 10 de `PostgresEventRepositoryTests` con PostgreSQL habilitado.
- **3 regresiones Python correctas** y **15 comprobaciones HTTP de humo correctas** sobre la aplicación empaquetada.
- HTTP y PostgreSQL reales: eventos de tres fuentes con identificador compartido, orden entre fuentes empatadas, página con continuación, fidelidad del evento, rechazo de parámetros con forma de inyección y reenvío sin filas duplicadas.
- Aplicación empaquetada y PostgreSQL reales: POST seguido de GET con evento completo, 503 durante caída de la base de datos y recuperación del histórico con datos idénticos después de recrear el contenedor conservando su volumen.
- HTTP con repositorio de prueba: seguimiento completo de `next`, valores predeterminados/ explícitos, colección vacía, desplazamiento posterior al final, contexto `/siem`, cabeceras de host reenviado, errores genéricos y validación de parámetros.
- Pruebas JDBC con objetos de registro: SQL parametrizado, valores enlazados, timeout configurado, cierre de recursos y mapeo compartido. No se presentan como ejecución contra PostgreSQL.

Informe generado en `target/sem66/report.json` y resultados JUnit en `target/surefire-reports/`; son artefactos locales de construcción, no evidencia de CI.
