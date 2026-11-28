# Verificación del Compose del SIEM · SEM-131

## Resultado del ensayo del 27/11/2026

El SIEM se probó con OpenAPI `0.5.0`, PostgreSQL y el publicador del IDS. Se aplicó un ajuste local de Compose para conectar Identidad y aprovisionar `svc-ids`. El ensayo se realizó con datos sintéticos, credenciales desechables y sin publicar puertos de los servicios.

| Componente | Revisión |
| --- | --- |
| Compose base, Identidad 1.4.0 e IDS | [`67371c401b64d2d52ec340eb7825094fdb7d9ae2`][base] |
| Candidata SIEM | [`a8aa4a465ec0f7f3304aa0eafa1054e812679294`][siem] más el ajuste de `Cache-Control` en `SOURCE_MISMATCH`, después registrado en [`19de2cc`][fix] |
| Huella SHA-256 de los cambios Java probados | `07064ba6be76da4c6f31e99f0e56607173fd87256cd1d88076aa0b2de35eb1f5` |

| Comprobación | Resultado |
| --- | --- |
| Arranque | PostgreSQL, Identidad, SIEM e IDS sanos. |
| Ingesta | `POST /events` con `svc-ids` devolvió `200` para `SEM-131-IDS-9dac55333e714c32a751710a719df225`. El acuse confirmó el mismo identificador. |
| Histórico | `GET /events` con rol `analista` devolvió `200` y recuperó íntegro ese evento. |
| Correspondencia entre cuenta y origen | Un evento sintético con origen ajeno devolvió `403 SOURCE_MISMATCH` y no apareció en el histórico. En la candidata original faltaba `Cache-Control: no-store`. Tras aplicar el ajuste, la respuesta incluyó la cabecera. |
| Regresión Java | 160 pruebas ejecutadas con PostgreSQL real, 0 fallos, 0 errores y 0 omitidas. |
| Verificación del contrato | 6 ejemplos de evento, fixtures de alertas, referencias de OpenAPI y casos positivos y negativos del histórico superaron `scripts/verify-contract.py`. |
| Limpieza | Se retiraron los contenedores, las redes y el volumen desechable del ensayo. |

El resultado corresponde al entorno local descrito. La validación de entrega se registra sobre la revisión acordada del Compose común.

## Resultado de la candidata del 28/11/2026

La candidata local `4ec4a4ce12591fd7d391c7a86a5ba29a461b1c29` se montó sobre `main` en `e57da2e` con las PR #100, #118 y #123. El OpenAPI `0.5.0` coincide con el congelado. Para el ensayo se usó el mapeo del publicador IDS de la [PR #132][ids-compose] mediante un ajuste local de Compose.

- Identidad, PostgreSQL, SIEM, IDS y Dashboard arrancaron correctamente. `POST /events` con `svc-ids` y `GET /events` con un analista devolvieron `200`. El identificador `SEM-131-IDS-f10d5da186ff4cf3837fa941ef254154` coincide en el acuse y en el histórico.
- El proxy de Dashboard recuperó el evento y su alerta. Con PostgreSQL detenido, la API de salud devolvió `200` y el histórico devolvió `503 STORAGE_UNAVAILABLE` a través del proxy.
- Para SCRUM-56, los eventos de prueba P004 y P005 enviados por el publicador real del IDS devolvieron `200`. El reenvío idéntico dejó una sola entrada y el mismo ID con contenido distinto devolvió `409 EVENT_ID_CONFLICT`.
- Se retiraron los recursos de Docker de ambos ensayos. La persistencia de alertas se comprueba en el ensayo separado de SEM-149.

El [CI de la PR de prueba #133][ci-133] validó la combinación #123 + #132. Queda ejecutar el CI sobre el SHA de entrega y repetir la prueba con la revisión acordada del Compose común.

## Procedimiento de repetición

1. Registra los SHA exactos de la rama de integración del Compose, la candidata SIEM, Identidad e IDS. Usa un proyecto Compose desechable y un volumen PostgreSQL vacío. Comprueba que el SIEM tiene el perfil `persistence`, conexión a PostgreSQL y `IDENTITY_URL` accesible.
2. Configura `SERVICE_PASSWORD_IDS` en Identidad para sembrar `svc-ids`. El IDS debe usar `IDS_SERVICE_USERNAME=svc-ids` y recibir el mismo valor en `IDS_SERVICE_PASSWORD`. Su `SIEM_URL` debe apuntar a `http://siem:80/events`.
3. Arranca `identidad`, `siem-db`, `siem` e `ids` y comprueba que están sanos. Usa el publicador del IDS (`util.siem_publisher.publish_event`) para enviar un evento sintético con `source: ids` e identificador único. Comprueba el `200` y la coincidencia del `event_id` en el acuse.
4. Consulta `GET /events` con el Bearer de una cuenta `analista` o `admin` y compara el evento completo. Comprueba que un evento sintético con un origen ajeno a `svc-ids` recibe `403 SOURCE_MISMATCH` y `Cache-Control: no-store`, y queda fuera del histórico.
5. Guarda los SHA, códigos HTTP e identificadores de prueba. Usa credenciales de laboratorio y excluye sus valores y los tokens de la evidencia. Retira el proyecto y el volumen desechable al acabar.

## Estado de la entrega

Queda por fijar la revisión del Compose común que incluya el mapeo de la cuenta del IDS y la revisión candidata del SIEM con la corrección. Los resultados del ensayo común se registran en [SEM-131][sem131] y la entrega al Scrum de Scrums se sigue en [SCRUM-79][scrum79].

[base]: https://github.com/org-software-ciber-2627/software-ciber-2627/commit/67371c401b64d2d52ec340eb7825094fdb7d9ae2
[siem]: https://github.com/org-software-ciber-2627/software-ciber-2627/commit/a8aa4a465ec0f7f3304aa0eafa1054e812679294
[sem131]: https://moncholi.atlassian.net/browse/SEM-131
[scrum79]: https://scrum-de-scrums.atlassian.net/browse/SCRUM-79
[fix]: https://github.com/org-software-ciber-2627/software-ciber-2627/commit/19de2cc2cb75eb62b74eba644228b167fc5af758
[ids-compose]: https://github.com/org-software-ciber-2627/software-ciber-2627/pull/132
[ci-133]: https://github.com/org-software-ciber-2627/software-ciber-2627/actions/runs/46050591445/job/140680609947
