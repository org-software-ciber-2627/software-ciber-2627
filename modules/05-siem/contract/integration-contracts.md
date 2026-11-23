# Inventario de contratos de integración del SIEM

## Alcance y referencias de versión

Inventario técnico de SEM-123, parte de SEM-116. Recoge interfaces, ejemplos, versiones, discrepancias y decisiones pendientes entre el SIEM y los demás módulos. No introduce cambios en las APIs ni acredita acuerdos o ejecuciones que no se hayan verificado.

Fecha de revisión: 19/11/2026. La referencia de `main` es `5deed65fd77fad738fb9484b07299a2dd06f92d6`. Las observaciones sobre el código corresponden a revisión estática. Las evidencias anteriores se enlazan como antecedentes y no se presentan como pruebas repetidas en esta revisión.

| Referencia | Versión revisada | Situación |
| --- | --- | --- |
| Base común | [`main`, `5deed65`][main] | Contiene SIEM, contrato G1 y la integración de SOAR revisados. OpenAPI SIEM `0.3.0-sprint2`; G1 `1.3.0`. |
| IDS | [`equipo-02-ids`, `e8c80d5`][ids-branch] | El procesamiento periódico y los cambios administrativos están en la rama de equipo. Se distinguen del `main` revisado. |
| Honeypot | [`equipo-03-honeypot`, `94ab043`][honeypot-branch] | Cola y reintentos disponibles en la rama de equipo, todavía fuera de la base `main` indicada. |
| Pentesting | [`equipo-08-pentesting/LV8-29-interfaz-interactiva`, `055ecbd`][pentesting-branch] | Generador y exportación de eventos disponibles en esa rama. La aplicación completa no forma parte de la base `main` revisada. |
| Requisitos de despliegue SIEM | [SEM-128, commit `0eec80c`][compose-guide] | Guía publicada en la rama SEM-118. Especifica una propuesta de integración, no un cambio ya incorporado al Compose raíz. |

Una fusión en una rama de equipo no equivale a una incorporación a `main`. La compatibilidad de una muestra con el esquema tampoco demuestra publicación HTTP, persistencia, aceptación semántica o funcionamiento de consumidores reales.

## Interfaces vigentes del SIEM

Fuente de referencia: [OpenAPI](openapi.json). Acceso interno: `http://siem:80`; acceso local del Compose revisado: `http://localhost:8005`.

| Método y ruta | Uso | Respuesta y errores publicados |
| --- | --- | --- |
| `GET /health` | Compose, CI y consulta de salud | 200 con `status` y `module`. La implementación revisada no comprueba PostgreSQL. |
| `POST /events` | Recepción de un evento de G2, G3, G4 o G8 | 200 tras almacenar o reconocer un reenvío idéntico; 400 inválido; 409 conflicto; 413 tamaño; 415 contenido; 503 almacenamiento; 507 almacén de alertas lleno. |
| `GET /events` | Histórico persistido | 200 con `events`, `next_offset`, `next`; 400 consulta inválida; 503 almacenamiento o timeout; 500 error inesperado. |
| `GET /alerts` | Consumo de alertas por SOAR y Dashboard | 200 con `{"alerts": [...]}`, también vacío; 503/500 ante fallo de consulta. |
| `GET /alerts/{id}` | Detalle por `alert_id` | 200 con la alerta; 404 `ALERT_NOT_FOUND`; 503/500 ante fallo de consulta. |

Los errores gestionados del SIEM utilizan `error.code` y `error.message`. Un fallo de consulta no se representa como una lista vacía. Los errores de G1 mantienen el formato propio de su API; no se presupone que coincida con el del SIEM.

La base revisada no implementa autenticación ni autorización. Los futuros 401/403 y el error propuesto `IDENTITY_UNAVAILABLE` requieren acuerdo, actualización de contrato e implementación; no se describen como respuestas ya activas.

## Formato y comportamiento comunes

### Eventos de entrada

La referencia es [event-schema.json](event-schema.json), coherente con `SecurityEvent` de OpenAPI.

| Elemento | Regla vigente |
| --- | --- |
| Objeto raíz | Un evento por petición con exactamente `event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description`, `details`. No se admiten propiedades raíz adicionales. |
| Identidad | `event_id` de 1 a 128 caracteres `[A-Za-z0-9._:-]`; no se exige UUID. La identidad persistida es `(source, event_id)`. |
| Fecha | `timestamp` representa una fecha válida UTC terminada en `Z`. |
| Origen | `ids`, `honeypot`, `scanner`, `pentesting`. |
| Severidad de evento | `info`, `low`, `medium`, `high`, `critical`. |
| Textos | `event_type`, `title` y `description` no pueden ser vacíos ni contener solo espacios. |
| Datos específicos | `details` es un objeto abierto. No se añaden campos internos obligatorios por productor en este inventario. |

Un evento informativo se guarda en el histórico sin generar una alerta. Los datos que PostgreSQL no puede representar se rechazan conforme al [contrato de ingesta](sem65-ingestion-proposal.md).

La respuesta 200 confirma almacenamiento o reconocimiento de un reenvío idéntico, con el mismo `event_id` en el acuse. Misma identidad con contenido distinto produce 409 `EVENT_ID_CONFLICT`; no sobrescribe el original. JSONB compara contenido y estructura, sin prometer conservación del orden de claves ni de la escritura original de números. Los reenvíos deben conservar identidad, fecha y contenido.

Un 507 `STORAGE_FULL` puede producirse después de guardar el evento: el almacén de alertas está lleno. Un reenvío idéntico puede crear posteriormente la alerta si hay capacidad. Hay que acordar cómo informa y recupera cada productor este resultado parcial.

Con `persistence` activo, PostgreSQL debe estar disponible al arrancar. Sin ese perfil o con almacenamiento inaccesible durante una petición válida, la ingesta o el histórico responden 503. Un fallo de arranque no dispone de respuesta HTTP.

### Histórico y alertas

- [Histórico](history-events.md): `limit` predeterminado 100, entre 1 y 500; `offset` predeterminado 0, sin desbordar `offset + limit`. Solo se admiten los parámetros publicados. Orden `occurred_at DESC, source ASC, event_id ASC`. `next` conserva el límite; al terminar, `next` y `next_offset` son nulos. La paginación OFFSET no mantiene una instantánea ante inserciones concurrentes.
- [Alertas](sem68-alert-query-contract.md): cada alerta conserva el evento y añade `alert_id`, `source_ip`, `target_ip`. No incluye `priority`, `status`, `risk_score`, `recommended_action` ni `related_events`. Se conserva `details`; una lista de destinos P005 no se reduce a una única IP.
- Las alertas públicas admiten `low`, `medium`, `high`, `critical`. El listado no tiene filtros, paginación ni orden garantizado; Dashboard ordena en cliente.
- Las alertas están en memoria y se pierden al reiniciar el SIEM. Los eventos persistidos permanecen en PostgreSQL. SEM-121 aborda la persistencia de alertas.

## Matriz de integraciones y ejemplos

Los ejemplos enlazados son datos de laboratorio o referencias de código. No acreditan entregas reales en el despliegue actual.

| Equipo | Interfaz y datos | Referencia o ejemplo | Estado de la revisión |
| --- | --- | --- | --- |
| G1 · Identidad | El SIEM presentará el token del llamante a `GET /auth/validate`. `GET /secrets/{clave}` exige rol `servicio`; el lector del secreto PostgreSQL está por concretar. | [OpenAPI G1][identity-contract] y [resumen compartido][identity-summary]. | Contrato disponible; integración y acuerdos específicos del SIEM pendientes. Véase SEM-132. |
| G2 · IDS | `POST /events`, `source: ids`; P004 `brute_force`, P005 `endpoint_scan`. | [Ejemplo P004 del SIEM](../src/test/resources/ids/p004.json), [ejemplo P005 de G2 adaptado a datos de prueba](examples/grupo_2_ids_p005.json) y [publicador HTTP][ids-publisher-124]. | G2 confirma el envío al cierre de la detección y el reenvío del evento original. El publicador está en su rama; falta verificarlo en el Compose común. |
| G3 · Honeypot | `POST /events`, `source: honeypot`; `intento_login`, `fuerza_bruta`, `credenciales_por_defecto`; ampliar semántica de nuevos eventos. | [Contrato G3][honeypot-contract], [ejemplo actual del SIEM](examples/grupo_3_honeypot_actual.json) y [mapper G3][honeypot-mapper]. | Formato general alineado; revisar respuestas HTTP, versiones y nuevos tipos. Cola disponible en rama de equipo. |
| G4 · Escáner | `POST /events`, `source: scanner`, `details.target`; `port_open`, `service_detected`, `cve_detected`, `vulnerability_detected`. | [Contrato](scanner-events.md), [ejemplo de vulnerabilidad](examples/grupo_4_scanner.json), [ejemplo informativo](examples/grupo_4_scanner_info.json) y [PR #95][scanner-pr-95]. | G4 confirma la clasificación de inventario y el acuse de entrega. La PR está pendiente de aprobación e incorporación. |
| G6 · SOAR | `GET /alerts`; normaliza el contenedor `alerts`, crea incidentes y calcula prioridad. | [Contrato G6][soar-contract], [validador][soar-validator], [consumidor principal][soar-app] y [prioridad][soar-priority]. | Consumo implementado; falta admitir o excluir expresamente `pentesting`, coordinar autenticación y configurar ejecución real. |
| G7 · Dashboard | `GET /alerts` y detalle mediante proxy; muestra eventos convertidos en alertas. Consume también incidentes de G6. | [Cliente SIEM][dashboard-siem], [contrato G7][dashboard-contract], [cliente SOAR][dashboard-soar]. | Alertas apuntan al SIEM real; incidentes todavía apuntan a un mock en la referencia revisada. El histórico puede contener eventos sin alerta. |
| G8 · Pentesting | Eventos `source: pentesting`, `event_type: vulnerability_detected`; `details.target` conserva la URL. | [Ejemplo del SIEM](examples/grupo_8_pentesting.json), [ejemplo de G8][pentesting-example], [mapper][pentesting-mapper], [exportación][pentesting-controller]. | JSON exportable en la rama; envío HTTP y contrato de campaña pendientes de cierre. |

### Muestras que requieren precisión

- [grupo_2_ids_ejemplo_propuesto.json](examples/grupo_2_ids_ejemplo_propuesto.json) es el antecedente de `port_scan`. El [ejemplo actual de P005](examples/grupo_2_ids_p005.json) conserva los campos y tiempos del mensaje de G2 con direcciones de documentación.
- En P005, `target_ips`, `ports`, `connections` y la ventana se conservan dentro de `details`. El campo público `target_ip` de la alerta puede ser nulo.
- El contrato de G3 enumera `escaneo`, sin que las referencias revisadas acrediten su publicación efectiva. El README sí identifica el envío del resumen de rechazos como trabajo pendiente. Acordar tipos, detalles y severidades sin confundir catálogo documentado con función implementada.
- Para G4, `port_open` y `service_detected` son inventario y se emiten solo con `info`. El uso de `low` observado en la base del 19/11 queda como antecedente de C01.

## Discrepancias y dependencias identificadas

Cada fila distingue el estado observado en la versión revisada de las comprobaciones que quedan para la integración.

| ID y tipo | Evidencia y efecto | Grupo responsable y siguiente paso |
| --- | --- | --- |
| C01 · Severidad de inventario | El [parser][scanner-parser] y las [pruebas][scanner-tests] de la base del 19/11 usaban `low` para `port_open` y `service_detected`. G4 confirma que ambos tipos son exclusivamente `info` en la [PR #95][scanner-pr-95]. Las severidades `low`, `medium`, `high` y `critical` quedan reservadas a los hallazgos del Escáner. | Corregido en el código de la PR. G4/G5: verificar la revisión integrada y que el inventario queda en el histórico sin generar alerta. |
| C02 · Confirmación de entrega | El [publicador de la base del 19/11][scanner-jobs] no comprobaba el acuse. G4 confirma el cambio en el [publicador de la PR #95][scanner-pr-95-jobs]: HTTP `200`, `status: success` y coincidencia exacta de `event_id`. Los rechazos y los errores de red se registran en `siem_delivery` sin detener el escaneo. | Corregido en el código de la PR. G4/G5: enlazar la evidencia del ensayo comunicado y comprobar el acuse, la persistencia y un fallo de entrega en la versión integrada. |
| C03 · Publicación de G2 | El [flujo anterior][ids-main-branch] guardaba las detecciones en `events.json`. La rama de G2 en `6dcc265` [publica tras procesar el lote][ids-publish-flow-124], conserva el registro local y configura `SIEM_URL` para llegar al SIEM en Compose. El publicador aún está fuera de `main`. | G2/G5: incorporar la revisión al entorno común conservando la [configuración de PostgreSQL de main][siem-compose-main-124]. Verificar la ingesta y el acuse en SEM-127. |
| C04 · Cierre y reenvío de P004/P005 | G2 confirma que publicará las detecciones cerradas y que cada reenvío conserva la misma identidad, fecha y contenido. El [publicador][ids-publisher-124] copia el cuerpo y comprueba HTTP `200` con el mismo `event_id`, pero actualmente lleva a reintento también respuestas definitivas como `409`. | G2/G5: contrastar en SEM-127 el cierre de detecciones entre lotes y el tratamiento de rechazos definitivos para que queden visibles sin reintentarlos automáticamente. |
| C05 · Configuración y versión G3 | En el [Compose base][compose], Honeypot no recibe `SIEM_URL`; el [emisor base][honeypot-sender-main] apunta por defecto al mock local. La [rama de G3][honeypot-sender-branch] incorpora cola y reintentos. | G3/G7: incorporar destino real y versión de envío; G5 verifica la ingesta cuando exista almacenamiento común. |
| C06 · Documentación de respuestas | [Contrato G3][honeypot-contract] menciona 201/422. La [evidencia histórica SIEM](../docs/hu5-integracion-honeypot.md) cita `EVENT_CONFLICT`. El contrato vigente usa 200/400 y `EVENT_ID_CONFLICT`. | G3/G5: actualizar documentos actuales y mantener identificadas las evidencias históricas. Acordar recuperación de 503/507 y reenvíos sin cambiar contenido. |
| C07 · Eventos nuevos G3 | G3 publica un [ejemplo de `escaneo`][honeypot-examples-124], aunque en el flujo revisado no se ha confirmado su emisión. El [resumen de rechazos][honeypot-rejections-124] se guarda localmente. | G3/G5: confirmar qué tipos entran en el escenario. Si se publicará el resumen, acordar su JSON y severidad. |
| C08 · Catálogo de origen de G6 | [Validador SOAR][soar-validator] solo admite `ids`, `honeypot`, `scanner`; el contrato SIEM admite también `pentesting`. | G6/G5: ampliar el consumidor o documentar una exclusión acordada; comprobar un caso G8 de extremo a extremo. |
| C09 · Recorrido real de consumidores | El [Compose][compose] deja el sondeo SOAR en 0 por defecto; [Dashboard][dashboard-soar] lee un mock de incidentes; [notify][soar-playbook] depende de un destino provisional. | G6/G7: acordar sondeo, API real de incidentes y acción efectiva del playbook. G5 coordina la trazabilidad en SEM-119. |
| C10 · Publicación e identidad G8 | [README de la rama][pentesting-readme] declara pendiente el envío HTTP. El [mapper][pentesting-mapper] usa fecha actual cuando falta y un identificador con hash reducido; hay riesgo de reenvíos distintos o colisiones. | G8/G5: concretar publicador, identidad y fecha estables, y contrato de campaña. El formato válido no demuestra idempotencia ni publicación. |
| C11 · Identidad y permisos | [G1][identity-code] precarga una cuenta `servicio` y comprueba solo el rol al leer secretos. La base SIEM no aplica IAM. | G1/G5: SEM-132 cierra identidad y validación; SEM-141/SEM-35 define permisos. SEM-123 enlaza sus acuerdos y versiones, sin definir otro mecanismo paralelo. |
| C12 · Persistencia común | [Compose raíz][compose] no incorpora PostgreSQL ni `persistence` para SIEM. La [guía SEM-128][compose-guide] está publicada fuera de `main` como propuesta. | G7/G5, SEM-118: incorporar configuración y suministro del secreto PostgreSQL; comprobar ingesta con un productor real. El lector de G1 y la rotación siguen por acordar. |
| C13 · Documentación de consumidores | [Contrato G7][dashboard-contract] cita SIEM `0.2.0-sprint1-review`, omite `pentesting` y conserva descripciones anteriores de G4/G6. | G7 con proveedores: contrastar contra contratos vigentes y actualizar versiones y ejemplos. No deducir incompatibilidad de código solo por un README antiguo. |
| C14 · Filtros previstos | [SEM-28][jira-28] prevé fuente, severidad e intervalo temporal. El histórico actual solo acepta `limit` y `offset`; parámetros desconocidos producen 400. | G5/G7, SEM-125/SEM-116: acordar nombres, tipos, límites, extremos temporales y conservación en `next` antes del 26/11; implementar después en SEM-28. |
| C15 · Severidad, prioridad y correlación | El SIEM conserva `severity`; [G6 calcula `priority`][soar-priority]. [SEM-119][jira-119] identifica la ratificación en el SoS como pendiente. P004 reconocido no demuestra correlación adicional entre fuentes. | G5/G6/SoS: registrar cómo se satisface el escenario común, señales, reglas y trazabilidad. No añadir `priority` a la alerta ni declarar cerrado ese acuerdo unilateralmente. |
| C16 · Esquema común | [shared/event-schema.json][shared-schema] sigue siendo un placeholder de tipo objeto. El job común no acredita las reglas del esquema local completo por el mero hecho de pasar. | G5/G7, SEM-120: acordar el esquema común y los ejemplos positivos/negativos del CI compartido. |

## Identidad: referencia a la subtarea especializada

[SEM-132][jira-132] define el acuerdo de autenticación con G1; la implementación corresponde a SEM-133 y sus pruebas posteriores. [SEM-141][jira-141] define la matriz de autorización. [SEM-125][jira-125] contrasta el resultado con los consumidores.

El borrador comunicado para SEM-132 propone validación remota por petición, ausencia de caché y denegación ante fallos de G1. Está pendiente de ratificación y de publicación del documento especializado `identity-auth.md`; no se enlaza un archivo inexistente ni se considera implementado.

Aspectos que deben quedar resueltos en esos acuerdos:

- Proteger `POST /events`, `GET /events`, `GET /alerts` y `GET /alerts/{id}`, conservando el acceso público a `GET /health` según el diseño acordado.
- Definir cuentas, entrega privada de credenciales, renovación mediante login y tratamiento de expiración/revocación.
- Definir la relación entre identidad validada, operaciones y `source` permitido. Tener rol `servicio` no identifica por sí solo al módulo.
- Registrar 401/403 y el fallo de Identidad diferenciado del almacenamiento. El código propuesto `IDENTITY_UNAVAILABLE` todavía no pertenece al OpenAPI base.
- Contrastar capacidad con G1. Una futura caché cambiaría la garantía de revocación y requeriría acuerdo, pruebas y versión efectiva.
- Coordinar la activación con productores, SOAR y Dashboard. Los emisores y el consumidor principal de G6 de la base revisada no envían token; la validación en el navegador no sustituye al control del backend.

El secreto PostgreSQL propuesto `siem_db_password` y su suministro se concretan en SEM-118 con G1/G7. Que G7 recupere ese secreto es una alternativa de despliegue pendiente de aceptación; no una obligación ya acordada. El inventario no publica credenciales ni replica la guía de despliegue.

## Decisiones que requieren confirmación

| Decisión | Capacidad actual y propuesta pendiente | Equipos y referencia |
| --- | --- | --- |
| Inventario del escáner | G4 confirma `info` para todo el inventario descrito. Pendiente de verificar la incorporación de la PR #95 y la ingesta en el Compose común. | G4/G5; C01 y SEM-127. |
| Cierre de detecciones | G2 confirma el envío de P004/P005 finalizados y el reenvío del evento original. Pendiente de verificación entre servicios y de revisar el tratamiento de errores permanentes. | G2/G5; C04 y SEM-127. |
| Nuevos eventos | Acordar ejemplos y severidades de G3 y alcance de campaña de G8. | G3/G5/G8; C07/C10. |
| Autenticación y permisos | Contrato de G1 disponible; propuesta SIEM todavía no ratificada. | G1/G5 y clientes; SEM-132, SEM-141 y SEM-125. |
| Filtros | Mantener compatible la consulta sin filtros; cerrar semántica y ejemplos antes de implementar. | G5/G7; SEM-28 y SEM-125. |
| Prioridad y escenario | El cálculo actual está en SOAR. Ratificar el reparto y qué señales se correlacionan para la demo común. | G5/G6/SoS; SEM-119. |
| Secretos y despliegue | Guía disponible; confirmar lector del secreto, arranque, redes, volumen, migraciones y rotación. | G1/G5/G7; SEM-118. |

Las confirmaciones deben registrar versión, equipos afectados y fecha efectiva. Este inventario distingue lo implementado de lo propuesto; no convierte un pendiente en acuerdo ni modifica estados de Jira.

### SEM-124 · Contraste con productores

Revisión del 23/11/2026. Para esta comprobación se revisó [`main` en `23b1a19`][sem124-main] y se fijaron las referencias de las ramas de cada productor. Las evidencias de esta tabla son ejemplos y código revisados de forma estática. Las pruebas entre servicios quedan para SEM-127.

| Productor | Ejemplos, código y acuerdos revisados | Verificación o confirmación pendiente |
| --- | --- | --- |
| G2 · IDS | G2 confirmó el envío de P004/P005 al cerrar la detección y el reenvío con el mismo ID, fecha y contenido. Ya disponemos del [ejemplo P004](../src/test/resources/ids/p004.json) y de la [muestra P005 comunicada por G2](examples/grupo_2_ids_p005.json), con datos de prueba. El [publicador en `6dcc265`][ids-publisher-124] usa `POST /events` con JSON y comprueba el acuse. La [suite de G2][ids-ci-124] pasó en esa revisión. | Probar con la revisión integrada que el SIEM persiste el evento y reconoce el reenvío sin duplicarlo. Contrastar el tratamiento de `409` y la recuperación de pendientes tras un fallo temporal. |
| G3 · Honeypot | Los [cuatro ejemplos de G3 en `94ab043`][honeypot-examples-124] incluyen `intento_login`, `fuerza_bruta`, `credenciales_por_defecto` y `escaneo`. El [emisor de esa rama][honeypot-sender-branch] reintenta el `503` con el JSON original y excluye el `507` del reintento automático. | Confirmar si `escaneo` se emitirá en el escenario y qué versión lo publicará. Si se enviará el resumen de rechazos, obtener su JSON y severidad. Usar datos sintéticos en las muestras compartidas. |
| G4 · Escáner | G4 identifica la [PR #95][scanner-pr-95] (`649cffb`) como la entrega pendiente de aprobación. Confirma `info` para `port_open` y `service_detected`, las cuatro severidades no informativas para `cve_detected` y `vulnerability_detected`, y `details.evidence` acotado a 300 caracteres o `null`. El [publicador][scanner-pr-95-jobs] exige `200` con `status: success` y el mismo `event_id`, y deja los fallos visibles en `siem_delivery`. G4 comunica una prueba de integración validada. | Pendientes la aprobación e incorporación de la PR y la referencia verificable de la prueba comunicada. SEM-127 comprobará el acuse y el histórico por `event_id`, además de la ausencia de alerta para el inventario `info`. |
| G8 · Pentesting | El [JSON de G8][pentesting-example] de la rama en `055ecbd` cumple el esquema de entrada. La [aplicación permite exportar los eventos][pentesting-controller]. | Confirmar si el escenario usará publicación directa o exportación. Si hay publicación, confirmar la versión y que el reenvío conserva ID, fecha y contenido. |

Las confirmaciones y sus referencias se registran en SEM-124. SEM-126 recogerá las versiones definitivas del contrato.

## Casos de verificación posteriores

Estos casos especifican comprobaciones necesarias; no se presentan como ejecutados en el despliegue común durante esta revisión.

| Caso | Resultado esperado o decisión previa |
| --- | --- |
| Evento real válido de G2/G3/G4/G8 | Acuse 200 con el identificador enviado y evento completo recuperable del histórico. Requiere configuración y publicador reales. |
| Reenvío idéntico / contenido cambiado | 200 y una fila / 409 `EVENT_ID_CONFLICT` con original conservado. |
| Inventario `info` | Evento persistido sin alerta; vulnerabilidades no informativas siguen su flujo normal. |
| P004/P005 | Conservar la detección finalizada y sus detalles, listas y nulos; no inventar una única IP de destino. |
| Error de formato, contenido o tamaño | Respuesta publicada, sin inserción ni exposición de datos internos. |
| Histórico y filtros | Paginación y errores actuales; futuros filtros solo contra versión acordada, conservados en `next`. |
| Alertas a G6/G7 | Campos preservados, detalle coherente, tratamiento de `pentesting` y ausencia de mocks del recorrido. |
| Identidad y permisos | Tokens reales válidos, ausentes, inválidos, expirados y revocados; permisos y fallos de G1 según el contrato definitivo. |
| Reinicio y almacenamiento | Eventos conservados; comprobar alertas persistidas cuando SEM-121 esté integrada. |
| Escenario común | Relación entre `source`/`event_id`, `alert_id` e `incident_id`, severidad y prioridad según el acuerdo del SoS. |

Se reutilizan las evidencias de [histórico](../docs/history-events-tests.md), [almacenamiento](../docs/sem66-storage-tests.md), [escáner](../docs/scanner-integration.md), [Honeypot](../docs/hu5-integracion-honeypot.md), [P004](../docs/sem29-deteccion-intentos-fallidos.md) y [consulta de alertas](../docs/hu16-acceptance.md) como antecedentes identificados por su propia versión. Sus resultados no se trasladan automáticamente a la plataforma actual.

### Comprobación local del inventario · 19/11/2026

Se comprobó la resolución de enlaces relativos y las referencias de versión. El verificador existente `scripts/verify-contract.py` pasó con los seis ejemplos de eventos, fixtures de alertas, catálogos de severidad, referencias OpenAPI y casos positivos/negativos del contrato del histórico. Se utilizaron dependencias en un entorno temporal externo, eliminado al terminar. Esta comprobación valida documentos y datos de prueba; no ejecutó servicios HTTP, PostgreSQL, Docker ni el escenario común.

## Cierre del inventario

SEM-123 entrega el mapa de interfaces, ejemplos, versiones y discrepancias con evidencia y siguiente acción por grupo. SEM-124/125 contrastan productores y consumidores; SEM-126 registra los acuerdos definitivos; SEM-127 ejecuta las pruebas de contrato reales.

Los puntos abiertos no impiden disponer de un inventario completo, pero sí deben resolverse o gestionarse antes de declarar cerrada la integración correspondiente. No se cambian código, APIs, permisos ni infraestructura mediante este documento.

[main]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/5deed65fd77fad738fb9484b07299a2dd06f92d6
[ids-branch]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/e8c80d5c4ddb9a5e6b21bcbb0291c577ba53107b/modules/02-ids
[ids-main-branch]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/e8c80d5c4ddb9a5e6b21bcbb0291c577ba53107b/modules/02-ids/src/main.py
[ids-p004]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/02-ids/src/patterns/brute_force.py
[ids-p005]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/02-ids/src/patterns/endpoint_scan.py
[honeypot-branch]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/94ab04328191730aaee561fd4a6e71d750f9dbf0/modules/03-honeypot
[honeypot-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/03-honeypot/contract/README.md
[honeypot-readme]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/03-honeypot/README.md
[honeypot-mapper]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/EventoMapper.java
[honeypot-sender-main]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/SiemSenderService.java
[honeypot-sender-branch]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/94ab04328191730aaee561fd4a6e71d750f9dbf0/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/SiemSenderService.java
[scanner-parser]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/04-escaner/src/parser.py
[scanner-tests]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/04-escaner/src/test_parser.py
[scanner-jobs]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/04-escaner/src/jobs.py
[soar-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/06-soar/contract/README.md
[soar-validator]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/06-soar/src/soar/normalization/schemas.py
[soar-app]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/06-soar/src/app.py
[soar-priority]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/06-soar/contract/priority.md
[soar-playbook]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/06-soar/src/soar/services/playbook_service.py
[dashboard-siem]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/07-dashboard/src/SIEM-client.js
[dashboard-soar]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/07-dashboard/src/SOAR-client.js
[dashboard-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/07-dashboard/contract/README.md
[pentesting-branch]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting
[pentesting-readme]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting/README.md
[pentesting-example]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting/mocks/siem_event_example.json
[pentesting-mapper]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting/web/src/main/java/grupo8/sw/services/SiemEventMapper.java
[pentesting-controller]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting/web/src/main/java/grupo8/sw/controllers/ResultadoJsonController.java
[identity-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/01-identidad/contract/openapi.yaml
[identity-summary]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/shared/auth-contract.md
[identity-code]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/01-identidad/src/app.py
[compose]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/docker-compose.yml
[compose-guide]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/0eec80c0c253568e09df622f96484daff7d13114/modules/05-siem/docs/common-compose-integration.md
[shared-schema]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/shared/event-schema.json
[jira-28]: https://moncholi.atlassian.net/browse/SEM-28
[jira-119]: https://moncholi.atlassian.net/browse/SEM-119
[jira-132]: https://moncholi.atlassian.net/browse/SEM-132
[jira-141]: https://moncholi.atlassian.net/browse/SEM-141
[jira-125]: https://moncholi.atlassian.net/browse/SEM-125
[sem124-main]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/23b1a19d42fcd92496906799e36dd5565bac3ef3
[ids-p004-example-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/23b1a19d42fcd92496906799e36dd5565bac3ef3/modules/02-ids/README.md#evento-generado
[ids-p005-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/c7811f0eda2637501ef1627942b53c8d08fe5159/modules/02-ids/src/patterns/endpoint_scan.py
[honeypot-examples-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/94ab04328191730aaee561fd4a6e71d750f9dbf0/modules/03-honeypot/contract/examples
[honeypot-rejections-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/94ab04328191730aaee561fd4a6e71d750f9dbf0/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/RechazoResumenService.java
[scanner-pr-95]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/95
[scanner-pr-95-jobs]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/649cffb229486866facadca1bff45127bca56561/modules/04-escaner/src/jobs.py
[ids-publisher-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/6dcc2658933e05f7369cb4edb19b0250bf369790/modules/02-ids/src/util/siem_publisher.py
[ids-publish-flow-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/6dcc2658933e05f7369cb4edb19b0250bf369790/modules/02-ids/src/main.py
[ids-ci-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/actions/runs/45191585007/job/137751037596
[siem-compose-main-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/96
