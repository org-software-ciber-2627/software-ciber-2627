# Inventario de contratos de integración del SIEM

## Alcance y referencias de versión

Inventario técnico de SEM-123, parte de SEM-116. Recoge interfaces, ejemplos, versiones, discrepancias y decisiones pendientes entre el SIEM y los demás módulos. No introduce cambios en las APIs ni acredita acuerdos o ejecuciones que no se hayan verificado.

Revisión inicial: 19/11/2026. La referencia de `main` es `5deed65fd77fad738fb9484b07299a2dd06f92d6`. Las observaciones sobre el código corresponden a revisión estática. Las evidencias anteriores se enlazan como antecedentes y no se presentan como pruebas repetidas en esta revisión.

| Referencia | Versión revisada | Situación |
| --- | --- | --- |
| Base común | [`main`, `5deed65`][main] | Contiene SIEM, contrato G1 y la integración de SOAR revisados. OpenAPI SIEM `0.3.0-sprint2`; G1 `1.3.0`. |
| IDS | [`equipo-02-ids`, `e8c80d5`][ids-branch] | El procesamiento periódico y los cambios administrativos están en la rama de equipo. Se distinguen del `main` revisado. |
| Honeypot | [`equipo-03-honeypot`, `94ab043`][honeypot-branch] | Cola y reintentos disponibles en la rama de equipo, todavía fuera de la base `main` indicada. |
| Pentesting | [`equipo-08-pentesting/LV8-29-interfaz-interactiva`, `055ecbd`][pentesting-branch] | Generador y exportación de eventos disponibles en esa rama. La aplicación completa no forma parte de la base `main` revisada. |
| Requisitos de despliegue SIEM | [SEM-128, commit `0eec80c`][compose-guide] | Guía publicada en la rama SEM-118. Especifica una propuesta de integración, no un cambio ya incorporado al Compose raíz. |

Última actualización: 27/11/2026. El contraste de SEM-124 incorpora las referencias del publicador de G8, la publicación de Identidad `1.4.0` y la tarea de G7 para el esquema compartido. La tabla de arriba conserva las referencias de partida.

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

La tabla corresponde a OpenAPI `0.3.0-sprint2`. La autenticación ratificada con G1 se implementa en la [PR #100][siem-auth-pr], en borrador al 24/11. La autorización por cuenta y origen se coordina en SEM-35.

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
| G1 · Identidad | El SIEM valida el token del llamante mediante `GET /auth/validate`. Las cuentas por módulo tienen rol `servicio`. | [Contrato ratificado con G1][identity-auth-24], [PR #100][siem-auth-pr] y [fusión de Identidad 1.4.0][identity-merge-26]. | Las cuentas de servicio de Identidad están en `main`. La #134 pasa sus variables a Identidad y la #132 aporta el mapeo del publicador IDS. La autorización se probó en local en SEM-131. |
| G2 · IDS | `POST /events`, `source: ids`; P004 `brute_force`, P005 `endpoint_scan`. | [Ejemplo P004 del SIEM](../src/test/resources/ids/p004.json), [ejemplo P005 de G2 adaptado a datos de prueba](examples/grupo_2_ids_p005.json) y [publicador HTTP][ids-publisher-124]. | El envío autenticado de la [PR #104][ids-auth-pr] está en `main`. Ingesta, histórico y reenvíos de P004/P005 verificados en el ensayo local del 28/11. Queda comprobar el Compose común. |
| G3 · Honeypot | `POST /events`, `source: honeypot`; `intento_login`, `fuerza_bruta`, `credenciales_por_defecto`, `escaneo` y `peticiones_rechazadas`. | [Revisión de integración `1461e51`][honeypot-integration-27], [mapper][honeypot-mapper-24] y [resumen con info](examples/grupo_3_honeypot_rechazos_info.json). | La entrega [#122][honeypot-main-28] está en `main`. Incluye el envío con `svc-honeypot` y el resumen con `info`. Pendiente de prueba en el Compose común. |
| G4 · Escáner | `POST /events`, `source: scanner`, `details.target`; `port_open`, `service_detected`, `cve_detected`, `vulnerability_detected`. | [Contrato](scanner-events.md), [ejemplo de vulnerabilidad](examples/grupo_4_scanner.json), [ejemplo informativo](examples/grupo_4_scanner_info.json) y [PR #124][scanner-pr-124]. | La PR #124 está abierta y su publicador usa Bearer de `svc-escaner`. Pendiente de prueba en el Compose común. |
| G6 · SOAR | Inicia sesión en Identidad con `svc-soar` y consulta solo `GET /alerts` con Bearer. Normaliza el contenedor `alerts`, crea incidentes y calcula prioridad. | [PR #120][soar-auth-pr-26], [consumidor][soar-app], [validador][soar-validator] y [prioridad][soar-priority]. | Ante un `401` del listado renueva el token y reintenta una vez. Un `401` persistente o un `503` se registra como error. Pendiente verificar con Identidad y SIEM reales. |
| G7 · Dashboard | `GET /alerts` y detalle mediante proxy; muestra eventos convertidos en alertas. Consume también incidentes de G6. | [Cliente SIEM][dashboard-siem], [contrato G7][dashboard-contract], [cliente SOAR][dashboard-soar-24]. | En `main`, el Dashboard consulta las APIs de alertas e incidentes. Falta la prueba conjunta. El histórico puede contener eventos sin alerta. |
| G8 · Pentesting | `POST /events` con Bearer de `svc-pentesting`, `source: pentesting`, `event_type: vulnerability_detected` y URL en `details.target`. | [Publicador en c3b8826][pentesting-client], [ejemplo de G8][pentesting-example] y [muestra para el CI][pentesting-ci-example]. | El publicador está en `equipo-08-pentesting/LV8-29-interfaz-interactiva`. El envío está desactivado por defecto. Falta aprovisionar la cuenta en el entorno, habilitar el envío y comprobar la recepción y el histórico. |

### Muestras que requieren precisión

- [grupo_2_ids_ejemplo_propuesto.json](examples/grupo_2_ids_ejemplo_propuesto.json) es el antecedente de `port_scan`. El [ejemplo actual de P005](examples/grupo_2_ids_p005.json) conserva los campos y tiempos del mensaje de G2 con direcciones de documentación.
- En P005, `target_ips`, `ports`, `connections` y la ventana se conservan dentro de `details`. El campo público `target_ip` de la alerta puede ser nulo.
- El [ejemplo histórico de G3](examples/grupo_3_honeypot_actual.json) y el resumen confirmado el 24/11 documentan tipos distintos. El catálogo actualizado está en SEM-124.
- Para G4, `port_open` y `service_detected` son inventario y se emiten solo con `info`. El uso de `low` observado en la base del 19/11 queda como antecedente de C01.

## Discrepancias y dependencias identificadas

Cada fila distingue el estado observado en la versión revisada de las comprobaciones que quedan para la integración.

| ID y tipo | Evidencia y efecto | Grupo responsable y siguiente paso |
| --- | --- | --- |
| C01 · Severidad de inventario | El [parser][scanner-parser] y las [pruebas][scanner-tests] de la base del 19/11 usaban `low` para `port_open` y `service_detected`. G4 confirma que ambos tipos son exclusivamente `info` en la [PR #95][scanner-pr-95]. Las severidades `low`, `medium`, `high` y `critical` quedan reservadas a los hallazgos del Escáner. | Corregido en el código de la PR. G4/G5: verificar la revisión integrada y que el inventario queda en el histórico sin generar alerta. |
| C02 · Confirmación de entrega | El [publicador de la base del 19/11][scanner-jobs] no comprobaba el acuse. G4 confirma el cambio en el [publicador de la PR #95][scanner-pr-95-jobs]: HTTP `200`, `status: success` y coincidencia exacta de `event_id`. Los rechazos y los errores de red se registran en `siem_delivery` sin detener el escaneo. | Corregido en el código de la PR. G4/G5: enlazar la evidencia del ensayo comunicado y comprobar el acuse, la persistencia y un fallo de entrega en la versión integrada. |
| C03 · Publicación de G2 | La [PR #104][ids-auth-pr] incorporó el publicador autenticado a `main`. La [PR #132][identity-compose-ids] conecta la credencial de `svc-ids` en Identidad y en el IDS. | G1/G7: acordar la revisión de Compose con ese mapeo. G2/G5: repetir la prueba local de SEM-131 en el entorno común. |
| C04 · Cierre y reenvío de P004/P005 | G2 confirma que publica las detecciones cerradas. En el [publicador corregido en `582dde5`][ids-publisher-124], un HTTP `409` se registra como rechazo definitivo y el evento sale de la cola automática. Ante fallos temporales como `503` o un timeout, el publicador conserva el ID, la fecha y el contenido. Un `200` con el mismo `event_id` elimina el pendiente. | Corregido en la rama de G2. SEM-127 comprobará el cierre entre lotes, el rechazo definitivo y la recuperación tras un fallo temporal con el SIEM real. |
| C05 · Configuración y versión G3 | La [revisión de integración `1461e51`][honeypot-integration-27] incluye HP-125 y HP-89 ([PR #127][honeypot-pr-127]). Su [Compose][honeypot-compose-27] conserva `honeypot-siem`, añade `honeypot-identidad` y define `start_period: 120s` para el Honeypot. | G1/G7: inyectar `SERVICE_PASSWORD_HONEYPOT` en Identidad y conservar su conexión a `honeypot-identidad`. G3/G7: pasar la misma credencial al Honeypot. G3/G5: esperar a que el servicio esté sano y comprobar el envío autenticado, el acuse y el histórico en SEM-127. |
| C06 · Documentación de respuestas | [Contrato G3][honeypot-contract] menciona 201/422. La [evidencia histórica SIEM](../docs/hu5-integracion-honeypot.md) cita `EVENT_CONFLICT`. El contrato vigente usa 200/400 y `EVENT_ID_CONFLICT`. | G3/G5: actualizar documentos actuales y mantener identificadas las evidencias históricas. Acordar recuperación de 503/507 y reenvíos sin cambiar contenido. |
| C07 · Catálogo y severidades G3 | G3 ratificó su mapa de severidades. El [publicador en `1461e51`][honeypot-summary-27] emite `peticiones_rechazadas` con `info`. | G3/G5: verificar en SEM-127 que el resumen aparece en el histórico y queda fuera de las alertas. |
| C08 · Catálogo de origen de G6 | El [validador de la revisión de referencia][soar-validator-24] admitía `ids`, `honeypot` y `scanner`. El [validador en la rama de integración de G6][soar-validator] admite también `pentesting`. G6 ratifica el tratamiento de los hallazgos de G8 con `event_type: vulnerability_detected`. | G5/G6/G8: verificar el recorrido adicional con servicios reales si se incorpora al ensayo. El caso principal sigue el P004 del IDS. |
| C09 · Recorrido real de consumidores | El [Compose revisado][compose-24] fija un sondeo SOAR predeterminado de 30 s y el [Dashboard][dashboard-soar-24] consulta el API de incidentes. La [PR #120][soar-auth-pr-26] incorpora el Bearer al sondeo de alertas de SOAR. | G6/G7: verificar login, `GET /alerts` autenticado, incidentes y visualización en Dashboard con el Compose común. G5 coordina la trazabilidad en SEM-119. |
| C10 · Publicación e identidad G8 | [c3b8826][pentesting-revision] incluye el [publicador HTTP][pentesting-client], el login con Identidad y la muestra del CI. El [mapper][pentesting-mapper] genera IDs deterministas y usa la fecha fija del análisis cuando el hallazgo carece de timestamp. | G7 mapea `SERVICE_PASSWORD_PENTESTING` a `SIEM_AUTH_PASSWORD` en el contenedor de G8. G8 configura `SIEM_AUTH_USER=svc-pentesting` y habilita `SIEM_ENABLED` para el ensayo. G5/G8 comprueban el envío autenticado, la estabilidad del reenvío y el histórico en SEM-127. |
| C11 · Identidad y permisos | [SEM-132][identity-auth-24] documenta las cuentas por módulo y SEM-35 define los permisos por cuenta y operación. El cliente SOAR usa el permiso de listado con `svc-soar`. | G1/G7: coordinar Identidad `1.4.0` y el aprovisionamiento de `svc-soar` antes de activar el SIEM autenticado en el Compose común. La misma credencial se inyecta como `SERVICE_PASSWORD_SOAR` en Identidad y como `SOAR_SERVICE_PASSWORD` en SOAR. `AUTH_URL` o `IDENTITY_URL` apunta a G1. |
| C12 · Persistencia común | La [PR #96][siem-compose-main-124] incorporó PostgreSQL y el perfil `persistence` al Compose común. | G1/G5/G7, SEM-118: verificar el suministro del secreto en el arranque común y validar la ingesta con un productor real. |
| C13 · Documentación de consumidores | [Contrato G7][dashboard-contract] cita SIEM `0.2.0-sprint1-review`, omite `pentesting` y conserva descripciones anteriores de G4/G6. | G7 con proveedores: contrastar contra contratos vigentes y actualizar versiones y ejemplos. No deducir incompatibilidad de código solo por un README antiguo. |
| C14 · Filtros previstos | [SEM-28][jira-28] prevé fuente, severidad e intervalo temporal. El histórico actual solo acepta `limit` y `offset`; parámetros desconocidos producen 400. | G5/G7, SEM-125/SEM-116: acordar nombres, tipos, límites, extremos temporales y conservación en `next` antes del 26/11; implementar después en SEM-28. |
| C15 · Severidad, prioridad y correlación | El SIEM conserva `severity` y [SOAR calcula `priority`][soar-priority]. G6 confirmó `high` → `high` para el caso de referencia. Para un hallazgo G8 `vulnerability_detected`, SOAR crea un incidente sin playbook y con prioridad según su severidad. | G5/G6: verificar la trazabilidad del P004 en [SEM-119][jira-119]. La muestra reproducible del caso principal se sigue en SEM-153. |
| C16 · Esquema común | La [PR #130][schema-pr-130] (DASHG7-166) sustituyó el esquema provisional en main. En la candidata, [shared/event-schema.json][shared-schema] coincide con el esquema del módulo SIEM. | En [SEM-140][jira-140] se registrarán el SHA del esquema y la ejecución del CI compartido con ejemplos válidos e inválidos. |
| C17 · Credencial del Escáner | En la [PR #124][scanner-pr-124], el Compose del Escáner usa `SIEM_SVC_USER=svc-escaner` por defecto y lee `SIEM_SVC_PASSWORD`. Identidad `1.4.0` aprovisiona esa cuenta con `SERVICE_PASSWORD_ESCANER`. | G1/G7: pasar `SERVICE_PASSWORD_ESCANER` a Identidad. G4/G7: pasar el mismo valor al Escáner como `SIEM_SVC_PASSWORD`. G4/G5: comprobar login y envío en SEM-127. |

## Identidad: referencia a la subtarea especializada

[SEM-132][jira-132] define el acuerdo de autenticación con G1; la implementación corresponde a SEM-133 y sus pruebas posteriores. [SEM-141][jira-141] define la matriz de autorización. [SEM-125][jira-125] contrasta el resultado con los consumidores.

El [contrato de identidad][identity-auth-24] documenta la validación remota por petición, sin caché, la denegación ante fallo de Identidad y `GET /health` público. La [PR #110][identity-release-26] incorporó Identidad `1.4.0` a `main` en [67371c4][identity-merge-26]. La [PR #134][identity-compose-g7] conecta las variables de las cuentas en Identidad. La [PR #132][identity-compose-ids] añade el mapeo del IDS. El [ensayo local de SEM-131](../docs/sem131-compose-verification.md) confirmó el recorrido autenticado de IDS con ese mapeo.

G1 y G5 documentaron que el SIEM leerá `siem_db_password` con `svc-siem`. SEM-118 contrasta con G7 el suministro del mismo valor a PostgreSQL y al SIEM durante el arranque.

### Referencia congelada del SIEM

El 26/11/2026 se ratificó [OpenAPI 0.5.0][siem-frozen-26] en la revisión `a8aa4a465ec0f7f3304aa0eafa1054e812679294` de la PR #118, que incluye la autenticación de la #100. El formato de eventos y alertas se mantiene. Las operaciones protegidas requieren Bearer y aplican la matriz de permisos por rol, cuenta y origen. `POST /events` conserva `507 STORAGE_FULL`: el evento se guarda y la alerta puede quedar pendiente por capacidad.

La fecha efectiva del contrato corresponde al acuerdo del 26/11. La activación en el Compose común depende de la disponibilidad de Identidad `1.4.0`, las cuentas de servicio y sus mapeos. La candidata se verifica en SEM-131. La persistencia de alertas se ensaya en una rama independiente. [SEM-126][jira-126] recoge el acuerdo y las referencias.

## Decisiones que requieren confirmación

| Decisión | Capacidad actual y propuesta pendiente | Equipos y referencia |
| --- | --- | --- |
| Inventario del escáner | G4 confirma `info` para todo el inventario descrito. PR #95 fusionada. Falta verificar la ingesta en el Compose común. | G4/G5; C01 y SEM-127. |
| Cierre de detecciones | G2 confirma el envío de P004/P005 finalizados y el reenvío del evento original. La corrección publicada en su rama separa los rechazos definitivos de los fallos temporales. | G2/G5; C04. Verificación entre servicios en SEM-127. |
| Catálogo G3 | La revisión de integración aplica el catálogo confirmado y el resumen con `info`. Falta comprobarlo entre servicios. | G3/G5; C07 y SEM-127. |
| Autenticación y permisos | Autenticación ratificada. Pendientes activación, permisos por cuenta y prueba entre servicios. | G1/G5 y clientes; SEM-132, SEM-141 y SEM-125. |
| Filtros | Mantener compatible la consulta sin filtros; cerrar semántica y ejemplos antes de implementar. | G5/G7; SEM-28 y SEM-125. |
| Prioridad y escenario | G6 confirma el tratamiento de los hallazgos G8 sin automatización. Queda verificar el recorrido principal con el P004 de G2. | G5/G6/G8/SoS; C08, C15 y SEM-119. |
| Secretos y despliegue | PostgreSQL incorporado al Compose. Verificar el suministro del secreto en el arranque común. | G1/G5/G7; SEM-118. |

Las confirmaciones deben registrar versión, equipos afectados y fecha efectiva. Este inventario distingue lo implementado de lo propuesto; no convierte un pendiente en acuerdo ni modifica estados de Jira.

### SEM-124 · Contraste con productores

Contraste inicial del 23/11/2026, actualizado con las confirmaciones de G3 y G8 del 24/11. Para la revisión inicial se consultó [`main` en `23b1a19`][sem124-main] y se fijaron las referencias de las ramas de cada productor. Las evidencias de esta tabla son ejemplos y código revisados de forma estática. Las pruebas entre servicios quedan para SEM-127.

| Productor | Ejemplos, código y acuerdos revisados | Verificación o confirmación pendiente |
| --- | --- | --- |
| G2 · IDS | G2 confirmó el envío de P004/P005 al cerrar la detección y el reenvío con el mismo ID, fecha y contenido. Disponemos del [ejemplo P004](../src/test/resources/ids/p004.json) y de la [muestra P005 de G2](examples/grupo_2_ids_p005.json), con datos de prueba. El [publicador en `582dde5`][ids-publisher-124] comprueba el acuse y aplica la política de reintentos de C04. La [suite de G2][ids-ci-124] superó 34 pruebas en esa revisión. | Comprobar la revisión integrada en SEM-127: persistencia, acuse con el mismo ID, reenvío sin duplicados y retirada de la cola ante un `409`. |
| G3 · Honeypot | El mapper aplica las cuatro severidades indicadas para los otros tipos. El [publicador en `1461e51`][honeypot-summary-27] emite `peticiones_rechazadas` con `info`, como en el [JSON de ejemplo](examples/grupo_3_honeypot_rechazos_info.json). | Comprobar el envío autenticado, el acuse y la presencia en el histórico sin alerta. |
| G4 · Escáner | La [PR #95][scanner-pr-95] incorporó la clasificación del inventario y la comprobación del acuse. La [PR #124][scanner-pr-124], abierta en `2077e1a`, añade el Bearer al envío. El [job de pruebas del Escáner][scanner-ci-27] pasó en el fork de G4. | SEM-127 comprobará el envío autenticado en el Compose común, el acuse con el mismo ID y la consulta en histórico. Los eventos de inventario con `info` deben quedar fuera de las alertas. |
| G8 · Pentesting | G8 entregó el publicador autenticado en [c3b8826][pentesting-revision], el [JSON de referencia][pentesting-example] y la [copia para `event-schema`][pentesting-ci-example]. | Verificar el envío habilitado con `svc-pentesting` en SEM-127. La evidencia acordada para los hallazgos directos de G8 en el 01/12 es la recepción y consulta en el histórico del SIEM. |

#### G3 · Severidades confirmadas por el productor

| Tipo | Severidad comunicada | Tratamiento en el SIEM |
| --- | --- | --- |
| `credenciales_por_defecto` | `high` | Histórico y alerta `high`. |
| `fuerza_bruta` | `medium` | Histórico y alerta `medium`. |
| `escaneo` | `low` | Histórico y alerta `low`. |
| `intento_login` | `low` | Histórico y alerta `low`. |
| `peticiones_rechazadas` | `info` | Solo histórico. La revisión de integración aplica esta severidad. |

La tabla es compatible con el contrato del SIEM. La [evaluación P004][siem-p004-24] se aplica exclusivamente a eventos de IDS con tipo `brute_force` y `details.rule_id` igual a `P004`. Las severidades de G3 no intervienen en esa evaluación. SEM-127 debe comprobar el volumen de alertas de `intento_login` y `escaneo` en el escenario, ya que ambas generan alertas individuales. La muestra del resumen conserva `source_ip`, `service`, `minuto` y `rechazos` y usa una dirección reservada para documentación.

#### G8 · Publicación, reenvíos y consumo

- El [mapper de G8][pentesting-mapper] genera un ID determinista a partir del análisis, la herramienta y el título. G8 reportó dos lecturas idénticas de un análisis y siete IDs distintos en ese caso. Queda verificar el reenvío con servicios reales y el caso de dos hallazgos distintos que compartan análisis, herramienta y título.
- La [comparación del SIEM en PostgreSQL][siem-replay-24] busca por `(source, event_id)` y compara `event_type`, `severity`, `title`, `description` y el `timestamp` original. Para filas antiguas sin el timestamp original compara el instante almacenado. En `details` aplica igualdad JSONB: el orden de las claves de objetos y la representación de números equivalentes (`1` y `1.0`) son indiferentes. El orden de los elementos de un array sí cuenta. El acuse normal es `200` con el mismo ID. Un cambio de contenido para la misma identidad devuelve `409 EVENT_ID_CONFLICT`.
- Para `503`, G8 confirma que reintentará el mismo JSON. En la [implementación revisada][siem-event-service-24], `507 STORAGE_FULL` indica que el evento está almacenado y que falta guardar su alerta por capacidad. G8 evitará el reintento en bucle. Un reenvío idéntico puede completar la alerta cuando haya capacidad. Mientras persista la saturación, el reenvío seguirá devolviendo `507`.
- Un hallazgo no informativo de `pentesting` queda en el histórico y genera una alerta del SIEM si hay capacidad. La URL permanece en `details.target` y el campo público `target_ip` puede quedar nulo. G6 ratifica que SOAR crea un incidente para `vulnerability_detected`, sin playbook y con prioridad según severidad. C08 y C15 recogen el acuerdo y la comprobación integrada pendiente.

Las confirmaciones de productores se registran en SEM-124. [SEM-126][jira-126] contiene el registro de versiones del contrato.

## Casos de verificación posteriores

Estos casos especifican comprobaciones necesarias; no se presentan como ejecutados en el despliegue común durante esta revisión.

| Caso | Resultado esperado o decisión previa |
| --- | --- |
| Evento real válido de G2/G3/G4/G8 | Acuse 200 con el identificador enviado y evento completo recuperable del histórico. Requiere configuración y publicador reales. |
| Reenvío idéntico / contenido cambiado | 200 y una fila / 409 `EVENT_ID_CONFLICT` con original conservado. |
| Eventos `info` de G3/G4 | Resumen de rechazos e inventario visibles en el histórico sin alerta; los eventos no informativos siguen su flujo de alertas. |
| Reenvío de G8 después de un 507 | El histórico conserva una sola fila. Con capacidad para alertas, el reenvío idéntico devuelve 200 y crea la alerta pendiente. |
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

SEM-123 entrega el mapa de interfaces, ejemplos, versiones y discrepancias con evidencia y siguiente acción por grupo. El contraste de SEM-124 incorpora las referencias del publicador autenticado de G8 y los ejemplos usados para la revisión. SEM-125 contrasta el comportamiento de los consumidores, SEM-126 registra los acuerdos definitivos y SEM-127 ejecuta las pruebas de contrato reales.

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
[soar-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/4df655064a75e4a0850d5c57a92c543fd338aa24/modules/06-soar/contract/README.md
[soar-validator]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/4df655064a75e4a0850d5c57a92c543fd338aa24/modules/06-soar/src/soar/normalization/schemas.py
[soar-app]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/4df655064a75e4a0850d5c57a92c543fd338aa24/modules/06-soar/src/app.py
[soar-auth-pr-26]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/120
[soar-priority]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/4df655064a75e4a0850d5c57a92c543fd338aa24/modules/06-soar/contract/priority.md
[soar-playbook]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/06-soar/src/soar/services/playbook_service.py
[dashboard-siem]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/07-dashboard/src/SIEM-client.js
[dashboard-soar]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/07-dashboard/src/SOAR-client.js
[dashboard-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/07-dashboard/contract/README.md
[pentesting-branch]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting
[pentesting-readme]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/055ecbd05b40553c111ad0e8db631c31e3f52f64/modules/08-pentesting/README.md
[pentesting-example]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/c3b882668a1f9f2893e13859a0e4f168f17b3ef1/modules/08-pentesting/docs/ejemplo-evento-siem.json
[pentesting-mapper]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/c3b882668a1f9f2893e13859a0e4f168f17b3ef1/modules/08-pentesting/web/src/main/java/grupo8/sw/services/SiemEventMapper.java
[pentesting-client]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/c3b882668a1f9f2893e13859a0e4f168f17b3ef1/modules/08-pentesting/web/src/main/java/grupo8/sw/services/SiemClient.java
[pentesting-ci-example]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/c3b882668a1f9f2893e13859a0e4f168f17b3ef1/modules/08-pentesting/contract/examples/pentesting_cabeceras_http.json
[pentesting-revision]: https://github.com/org-software-ciber-2627/software-ciber-2627/commit/c3b882668a1f9f2893e13859a0e4f168f17b3ef1
[identity-contract]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/01-identidad/contract/openapi.yaml
[identity-summary]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/shared/auth-contract.md
[identity-code]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/modules/01-identidad/src/app.py
[compose]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/5deed65fd77fad738fb9484b07299a2dd06f92d6/docker-compose.yml
[compose-guide]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/0eec80c0c253568e09df622f96484daff7d13114/modules/05-siem/docs/common-compose-integration.md
[shared-schema]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/main/shared/event-schema.json
[jira-28]: https://moncholi.atlassian.net/browse/SEM-28
[jira-119]: https://moncholi.atlassian.net/browse/SEM-119
[jira-132]: https://moncholi.atlassian.net/browse/SEM-132
[jira-141]: https://moncholi.atlassian.net/browse/SEM-141
[jira-125]: https://moncholi.atlassian.net/browse/SEM-125
[jira-126]: https://moncholi.atlassian.net/browse/SEM-126
[identity-release-26]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/110
[identity-merge-26]: https://github.com/org-software-ciber-2627/software-ciber-2627/commit/67371c401b64d2d52ec340eb7825094fdb7d9ae2
[schema-reference-27]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/779a7840ef784f8fc9ba278a9a5e1d7f529017fc/modules/05-siem/contract/event-schema.json
[jira-140]: https://moncholi.atlassian.net/browse/SEM-140
[siem-frozen-26]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a8aa4a465ec0f7f3304aa0eafa1054e812679294/modules/05-siem/contract/openapi.json
[sem124-main]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/23b1a19d42fcd92496906799e36dd5565bac3ef3
[ids-p004-example-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/23b1a19d42fcd92496906799e36dd5565bac3ef3/modules/02-ids/README.md#evento-generado
[ids-p005-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/c7811f0eda2637501ef1627942b53c8d08fe5159/modules/02-ids/src/patterns/endpoint_scan.py
[honeypot-examples-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/94ab04328191730aaee561fd4a6e71d750f9dbf0/modules/03-honeypot/contract/examples
[honeypot-rejections-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/94ab04328191730aaee561fd4a6e71d750f9dbf0/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/RechazoResumenService.java
[scanner-pr-95]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/95
[scanner-pr-95-jobs]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/649cffb229486866facadca1bff45127bca56561/modules/04-escaner/src/jobs.py
[ids-publisher-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/582dde5dbcb1f90563e952e54cfb7f17086689d1/modules/02-ids/src/util/siem_publisher.py
[ids-publish-flow-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/6dcc2658933e05f7369cb4edb19b0250bf369790/modules/02-ids/src/main.py
[ids-ci-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/actions/runs/45196741717/job/137769091367
[siem-compose-main-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/96
[main-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/a9843a0072d8c58b90db7ed1cfe91d5816530ffb
[identity-auth-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/contract/identity-auth.md
[siem-auth-pr]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/100
[ids-auth-pr]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/104
[honeypot-mapper-24]: https://github.com/CapitanPescanova/software-ciber-2627/blob/4699ac4a480cee514cf1ec402532fea10b719707/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/EventoMapper.java#L28-L36
[compose-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/docker-compose.yml
[dashboard-soar-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/07-dashboard/src/SOAR-client.js
[soar-validator-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/06-soar/src/soar/normalization/schemas.py#L46-L50
[siem-p004-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/src/main/java/com/ciberurjc/siem/services/RepeatedAuthenticationFailureEvaluator.java#L23-L31
[siem-replay-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/src/main/java/com/ciberurjc/siem/repositories/PostgresEventRepository.java#L52-L71
[siem-event-service-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/src/main/java/com/ciberurjc/siem/services/EventService.java#L47-L66
[honeypot-integration-27]: https://github.com/org-software-ciber-2627/software-ciber-2627/commit/1461e51df599e93e08d59ad321c956c35c432ad2
[honeypot-pr-127]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/127
[honeypot-compose-27]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/1461e51df599e93e08d59ad321c956c35c432ad2/docker-compose.yml
[honeypot-summary-27]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/1461e51df599e93e08d59ad321c956c35c432ad2/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/RechazoResumenSiemService.java
[scanner-pr-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/124
[scanner-ci-27]: https://github.com/k4r0n22/software-ciber-2627/actions/runs/45874394925/job/140097697264
[honeypot-main-28]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/122
[identity-compose-g7]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/134
[identity-compose-ids]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/132
[schema-pr-130]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/130
