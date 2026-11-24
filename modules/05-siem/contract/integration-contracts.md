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

Última actualización: 24/11/2026. El contraste de SEM-124 incorpora las confirmaciones de G3 y G8 y el [estado de main al 24/11][main-24]. La tabla de arriba conserva las referencias de partida.

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
| G1 · Identidad | El SIEM validará el token del llamante mediante `GET /auth/validate`. El acuerdo prevé cuentas por módulo con rol `servicio`. | [Contrato ratificado con G1][identity-auth-24] y [PR #100][siem-auth-pr]. | Pendientes G1 v1.4.0 y la prueba autenticada en el despliegue común. |
| G2 · IDS | `POST /events`, `source: ids`; P004 `brute_force`, P005 `endpoint_scan`. | [Ejemplo P004 del SIEM](../src/test/resources/ids/p004.json), [ejemplo P005 de G2 adaptado a datos de prueba](examples/grupo_2_ids_p005.json) y [publicador HTTP][ids-publisher-124]. | G2 confirma el envío al cierre de la detección y el reenvío del evento original. El envío autenticado figura en la [PR #104][ids-auth-pr]; falta verificarlo en el Compose común. |
| G3 · Honeypot | `POST /events`, `source: honeypot`; `intento_login`, `fuerza_bruta`, `credenciales_por_defecto`, `escaneo` y `peticiones_rechazadas`. | [Rama de G3][honeypot-branch-24], [mapper][honeypot-mapper-24] y [resumen con info](examples/grupo_3_honeypot_rechazos_info.json). | G3 confirma el catálogo y el cambio del resumen a `info`. La revisión disponible aún lo emite con `low`. |
| G4 · Escáner | `POST /events`, `source: scanner`, `details.target`; `port_open`, `service_detected`, `cve_detected`, `vulnerability_detected`. | [Contrato](scanner-events.md), [ejemplo de vulnerabilidad](examples/grupo_4_scanner.json), [ejemplo informativo](examples/grupo_4_scanner_info.json) y [PR #95][scanner-pr-95]. | G4 confirma la clasificación de inventario y el acuse de entrega. La PR #95 está fusionada. Falta la prueba en el Compose común. |
| G6 · SOAR | `GET /alerts`; normaliza el contenedor `alerts`, crea incidentes y calcula prioridad. | [Contrato G6][soar-contract], [validador][soar-validator], [consumidor principal][soar-app] y [prioridad][soar-priority]. | Consumo implementado; falta admitir o excluir expresamente `pentesting`, coordinar autenticación y configurar ejecución real. |
| G7 · Dashboard | `GET /alerts` y detalle mediante proxy; muestra eventos convertidos en alertas. Consume también incidentes de G6. | [Cliente SIEM][dashboard-siem], [contrato G7][dashboard-contract], [cliente SOAR][dashboard-soar-24]. | En `main`, el Dashboard consulta las APIs de alertas e incidentes. Falta la prueba conjunta. El histórico puede contener eventos sin alerta. |
| G8 · Pentesting | Eventos `source: pentesting`, `event_type: vulnerability_detected`; `details.target` conserva la URL. | [Ejemplo del SIEM](examples/grupo_8_pentesting.json), [ejemplo de G8][pentesting-example], [mapper][pentesting-mapper], [exportación][pentesting-controller]. | G8 confirma el envío directo para el 01/12. La revisión disponible permite exportar; El publicador HTTP sigue en desarrollo en LV8-87. |

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
| C03 · Publicación de G2 | El [flujo anterior][ids-main-branch] guardaba las detecciones en `events.json`. La rama de G2 en `6dcc265` [publica tras procesar el lote][ids-publish-flow-124], conserva el registro local y configura `SIEM_URL` para llegar al SIEM en Compose. El publicador aún está fuera de `main`. | G2/G5: incorporar la revisión al entorno común conservando la [configuración de PostgreSQL de main][siem-compose-main-124]. Verificar la ingesta y el acuse en SEM-127. |
| C04 · Cierre y reenvío de P004/P005 | G2 confirma que publica las detecciones cerradas. En el [publicador corregido en `582dde5`][ids-publisher-124], un HTTP `409` se registra como rechazo definitivo y el evento sale de la cola automática. Ante fallos temporales como `503` o un timeout, el publicador conserva el ID, la fecha y el contenido. Un `200` con el mismo `event_id` elimina el pendiente. | Corregido en la rama de G2. SEM-127 comprobará el cierre entre lotes, el rechazo definitivo y la recuperación tras un fallo temporal con el SIEM real. |
| C05 · Configuración y versión G3 | El [Compose del 19/11][compose] carecía de `SIEM_URL` para Honeypot. La [PR #102][honeypot-pr-102] apunta al SIEM común y la rama incorpora cola y reintentos. | G3/G7: verificar destino y credenciales en la rama de entrega. G3/G5: comprobar acuse y persistencia en SEM-127. |
| C06 · Documentación de respuestas | [Contrato G3][honeypot-contract] menciona 201/422. La [evidencia histórica SIEM](../docs/hu5-integracion-honeypot.md) cita `EVENT_CONFLICT`. El contrato vigente usa 200/400 y `EVENT_ID_CONFLICT`. | G3/G5: actualizar documentos actuales y mantener identificadas las evidencias históricas. Acordar recuperación de 503/507 y reenvíos sin cambiar contenido. |
| C07 · Catálogo y severidades G3 | G3 confirma su mapa de severidades y aporta `peticiones_rechazadas` con `info`. El [publicador revisado][honeypot-rejections-24] aún usa `low` para el resumen. | G5: confirmar a G3 la semántica propuesta. G3: entregar el cambio a `info`. G3/G5: comprobar en SEM-127 que el resumen queda en histórico sin alerta. |
| C08 · Catálogo de origen de G6 | SIEM admite `pentesting` y convierte los eventos no informativos en alertas. El [validador SOAR en main][soar-validator-24] admite `ids`, `honeypot` y `scanner`. | G5/G6/G8: acordar antes del 01/12 si el escenario exige incidentes de estos hallazgos. Si los exige, G6 debe admitir el origen y probar la trazabilidad con G5/G8. |
| C09 · Recorrido real de consumidores | El [Compose actualizado][compose-24] fija un sondeo SOAR predeterminado de 30 s y el [Dashboard][dashboard-soar-24] consulta el API de incidentes. | G6/G7: verificar sondeo, incidentes y acción del playbook con su destino real. G5 coordina la trazabilidad en SEM-119. |
| C10 · Publicación e identidad G8 | G8 confirma el envío directo el 01/12. La [revisión disponible][pentesting-readme-24] permite exportar y su [mapper][pentesting-mapper-24] usa aún un hash reducido y una fecha generada cuando falta la del hallazgo. | G8: completar LV8-87 y compartir rama, commit y JSON final antes del 26/11 según su comunicación. G5/G8: verificar publicación autenticada, estabilidad del reenvío y recuperación del 507. |
| C11 · Identidad y permisos | [SEM-132][identity-auth-24] documenta la ratificación de las cuentas por módulo. La [PR #100][siem-auth-pr] sigue en borrador. SEM-35 define los permisos por cuenta y operación. | G1/G5 y clientes: comprobar el despliegue de G1 v1.4.0, cerrar permisos y verificar el flujo con las cuentas definitivas. |
| C12 · Persistencia común | La [PR #96][siem-compose-main-124] incorporó PostgreSQL y el perfil `persistence` al Compose común. | G1/G5/G7, SEM-118: verificar el suministro del secreto en el arranque común y validar la ingesta con un productor real. |
| C13 · Documentación de consumidores | [Contrato G7][dashboard-contract] cita SIEM `0.2.0-sprint1-review`, omite `pentesting` y conserva descripciones anteriores de G4/G6. | G7 con proveedores: contrastar contra contratos vigentes y actualizar versiones y ejemplos. No deducir incompatibilidad de código solo por un README antiguo. |
| C14 · Filtros previstos | [SEM-28][jira-28] prevé fuente, severidad e intervalo temporal. El histórico actual solo acepta `limit` y `offset`; parámetros desconocidos producen 400. | G5/G7, SEM-125/SEM-116: acordar nombres, tipos, límites, extremos temporales y conservación en `next` antes del 26/11; implementar después en SEM-28. |
| C15 · Severidad, prioridad y correlación | El SIEM conserva `severity`; [G6 calcula `priority`][soar-priority]. [SEM-119][jira-119] identifica la ratificación en el SoS como pendiente. P004 reconocido no demuestra correlación adicional entre fuentes. | G5/G6/SoS: registrar cómo se satisface el escenario común, señales, reglas y trazabilidad. No añadir `priority` a la alerta ni declarar cerrado ese acuerdo unilateralmente. |
| C16 · Esquema común | [shared/event-schema.json][shared-schema] sigue siendo un placeholder de tipo objeto. El job común no acredita las reglas del esquema local completo por el mero hecho de pasar. | G5/G7, SEM-120: acordar el esquema común y los ejemplos positivos/negativos del CI compartido. |

## Identidad: referencia a la subtarea especializada

[SEM-132][jira-132] define el acuerdo de autenticación con G1; la implementación corresponde a SEM-133 y sus pruebas posteriores. [SEM-141][jira-141] define la matriz de autorización. [SEM-125][jira-125] contrasta el resultado con los consumidores.

El [contrato de identidad][identity-auth-24] documenta la ratificación del 20/11: validación remota por petición, sin caché, denegación ante fallo de Identidad y `GET /health` público. G1 anunció v1.4.0 con fecha efectiva 26/11. Queda comprobar la disponibilidad de las cuentas, los permisos de SEM-35 y el flujo con productores y consumidores.

G1 y G5 documentaron que el SIEM leerá `siem_db_password` con `svc-siem`. SEM-118 contrasta con G7 el suministro del mismo valor a PostgreSQL y al SIEM durante el arranque.

## Decisiones que requieren confirmación

| Decisión | Capacidad actual y propuesta pendiente | Equipos y referencia |
| --- | --- | --- |
| Inventario del escáner | G4 confirma `info` para todo el inventario descrito. PR #95 fusionada. Falta verificar la ingesta en el Compose común. | G4/G5; C01 y SEM-127. |
| Cierre de detecciones | G2 confirma el envío de P004/P005 finalizados y el reenvío del evento original. La corrección publicada en su rama separa los rechazos definitivos de los fallos temporales. | G2/G5; C04. Verificación entre servicios en SEM-127. |
| Catálogo G3 | G3 confirma severidades y resumen con `info`. Pendientes la validación de G5 y la revisión que aplica el cambio. | G3/G5; C07. |
| Autenticación y permisos | Autenticación ratificada. Pendientes activación, permisos por cuenta y prueba entre servicios. | G1/G5 y clientes; SEM-132, SEM-141 y SEM-125. |
| Filtros | Mantener compatible la consulta sin filtros; cerrar semántica y ejemplos antes de implementar. | G5/G7; SEM-28 y SEM-125. |
| Prioridad y escenario | SOAR calcula la prioridad. Acordar el tratamiento de los hallazgos G8 y validar el recorrido del escenario. | G5/G6/G8/SoS; C08 y SEM-119. |
| Secretos y despliegue | PostgreSQL incorporado al Compose. Verificar el suministro del secreto en el arranque común. | G1/G5/G7; SEM-118. |

Las confirmaciones deben registrar versión, equipos afectados y fecha efectiva. Este inventario distingue lo implementado de lo propuesto; no convierte un pendiente en acuerdo ni modifica estados de Jira.

### SEM-124 · Contraste con productores

Contraste inicial del 23/11/2026, actualizado con las confirmaciones de G3 y G8 del 24/11. Para la revisión inicial se consultó [`main` en `23b1a19`][sem124-main] y se fijaron las referencias de las ramas de cada productor. Las evidencias de esta tabla son ejemplos y código revisados de forma estática. Las pruebas entre servicios quedan para SEM-127.

| Productor | Ejemplos, código y acuerdos revisados | Verificación o confirmación pendiente |
| --- | --- | --- |
| G2 · IDS | G2 confirmó el envío de P004/P005 al cerrar la detección y el reenvío con el mismo ID, fecha y contenido. Disponemos del [ejemplo P004](../src/test/resources/ids/p004.json) y de la [muestra P005 de G2](examples/grupo_2_ids_p005.json), con datos de prueba. El [publicador en `582dde5`][ids-publisher-124] comprueba el acuse y aplica la política de reintentos de C04. La [suite de G2][ids-ci-124] superó 34 pruebas en esa revisión. | Comprobar la revisión integrada en SEM-127: persistencia, acuse con el mismo ID, reenvío sin duplicados y retirada de la cola ante un `409`. |
| G3 · Honeypot | G3 confirma las severidades de la tabla siguiente y aporta el [JSON del resumen](examples/grupo_3_honeypot_rechazos_info.json). El mapper publicado aplica las cuatro severidades indicadas para los otros tipos. El [resumen de la rama en 4699ac4][honeypot-rejections-24] aún usa `low`. | Recibir el commit con `info` y comprobar el envío autenticado, el acuse y la presencia en el histórico sin alerta. |
| G4 · Escáner | La [PR #95][scanner-pr-95] está fusionada. G4 confirma `info` para `port_open` y `service_detected`, las cuatro severidades no informativas para `cve_detected` y `vulnerability_detected`, y `details.evidence` acotado a 300 caracteres o `null`. El [publicador][scanner-pr-95-jobs] comprueba `200`, `status: success` y el mismo `event_id`. G4 comunicó una prueba de integración validada. | SEM-127 comprobará acuse, histórico y ausencia de alerta en inventario con `info`. |
| G8 · Pentesting | G8 confirma `POST /events` directo para el 01/12, con `source: pentesting`, `event_type: vulnerability_detected` y URL en `details.target`. El [ejemplo anterior][pentesting-example] conserva un formato compatible. En la [rama revisada][pentesting-readme-24] está disponible `GET /siem/eventos.json`. | Recibir rama, commit y JSON definitivo de LV8-87. Comprobar envío autenticado con `svc-pentesting` y coordinar el consumo de alertas con G6. |

#### G3 · Severidades confirmadas por el productor

| Tipo | Severidad comunicada | Tratamiento en el SIEM |
| --- | --- | --- |
| `credenciales_por_defecto` | `high` | Histórico y alerta `high`. |
| `fuerza_bruta` | `medium` | Histórico y alerta `medium`. |
| `escaneo` | `low` | Histórico y alerta `low`. |
| `intento_login` | `low` | Histórico y alerta `low`. |
| `peticiones_rechazadas` | `info` | Solo histórico. G3 anuncia el cambio desde `low`. |

La tabla es compatible con el contrato del SIEM. La [evaluación P004][siem-p004-24] se aplica exclusivamente a eventos de IDS con tipo `brute_force` y `details.rule_id` igual a `P004`. Las severidades de G3 no intervienen en esa evaluación. SEM-127 debe comprobar el volumen de alertas de `intento_login` y `escaneo` en el escenario, ya que ambas generan alertas individuales. La muestra del resumen conserva `source_ip`, `service`, `minuto` y `rechazos` y usa una dirección reservada para documentación.

#### G8 · Publicación, reenvíos y consumo

- G8 anuncia un identificador determinista, elimina la reducción `% 10000`, fija la fecha al detectar el hallazgo y conserva el evento original en los reenvíos. La estabilidad se comprobará sobre LV8-87.
- La [comparación del SIEM en PostgreSQL][siem-replay-24] busca por `(source, event_id)` y compara `event_type`, `severity`, `title`, `description` y el `timestamp` original. Para filas antiguas sin el timestamp original compara el instante almacenado. En `details` aplica igualdad JSONB: el orden de las claves de objetos y la representación de números equivalentes (`1` y `1.0`) son indiferentes. El orden de los elementos de un array sí cuenta. El acuse normal es `200` con el mismo ID. Un cambio de contenido para la misma identidad devuelve `409 EVENT_ID_CONFLICT`.
- Para `503`, G8 confirma que reintentará el mismo JSON. En la [implementación revisada][siem-event-service-24], `507 STORAGE_FULL` indica que el evento está almacenado y que falta guardar su alerta por capacidad. G8 evitará el reintento en bucle. Un reenvío idéntico puede completar la alerta cuando haya capacidad. Mientras persista la saturación, el reenvío seguirá devolviendo `507`.
- Un hallazgo no informativo de `pentesting` queda en el histórico y genera alerta del SIEM si hay capacidad. La URL permanece en `details.target` y el campo público `target_ip` puede quedar nulo. Que SOAR cree un incidente depende del acuerdo con G6 y de que su validador acepte el origen. C08 recoge esa dependencia.

Las confirmaciones y sus referencias se registran en SEM-124. SEM-126 recogerá las versiones definitivas del contrato.

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

SEM-123 entrega el mapa de interfaces, ejemplos, versiones y discrepancias con evidencia y siguiente acción por grupo. Las respuestas de G3 y G8 del 24/11 completan el contraste documental de SEM-124 y dejan identificadas las revisiones de implementación y pruebas pendientes. SEM-124/125 contrastan productores y consumidores; SEM-126 registra los acuerdos definitivos; SEM-127 ejecuta las pruebas de contrato reales.

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
[ids-publisher-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/582dde5dbcb1f90563e952e54cfb7f17086689d1/modules/02-ids/src/util/siem_publisher.py
[ids-publish-flow-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/6dcc2658933e05f7369cb4edb19b0250bf369790/modules/02-ids/src/main.py
[ids-ci-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/actions/runs/45196741717/job/137769091367
[siem-compose-main-124]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/96
[main-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/tree/a9843a0072d8c58b90db7ed1cfe91d5816530ffb
[identity-auth-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/contract/identity-auth.md
[siem-auth-pr]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/100
[ids-auth-pr]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/104
[honeypot-pr-102]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/102
[honeypot-branch-24]: https://github.com/CapitanPescanova/software-ciber-2627/tree/equipo-03-honeypot
[honeypot-mapper-24]: https://github.com/CapitanPescanova/software-ciber-2627/blob/4699ac4a480cee514cf1ec402532fea10b719707/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/EventoMapper.java#L28-L36
[honeypot-rejections-24]: https://github.com/CapitanPescanova/software-ciber-2627/blob/4699ac4a480cee514cf1ec402532fea10b719707/modules/03-honeypot/src/main/java/com/honeypot/honeypot/service/RechazoResumenSiemService.java#L27-L28
[compose-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/docker-compose.yml
[dashboard-soar-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/07-dashboard/src/SOAR-client.js
[soar-validator-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/06-soar/src/soar/normalization/schemas.py#L46-L50
[pentesting-readme-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/f0192530d76545f414f8a0ed36b3d770c5578442/modules/08-pentesting/README.md#L33-L37
[pentesting-mapper-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/f0192530d76545f414f8a0ed36b3d770c5578442/modules/08-pentesting/web/src/main/java/grupo8/sw/services/SiemEventMapper.java#L66-L77
[siem-p004-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/src/main/java/com/ciberurjc/siem/services/RepeatedAuthenticationFailureEvaluator.java#L23-L31
[siem-replay-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/src/main/java/com/ciberurjc/siem/repositories/PostgresEventRepository.java#L52-L71
[siem-event-service-24]: https://github.com/org-software-ciber-2627/software-ciber-2627/blob/a9843a0072d8c58b90db7ed1cfe91d5816530ffb/modules/05-siem/src/main/java/com/ciberurjc/siem/services/EventService.java#L47-L66
