# Estado de integración · Equipo 5 · Sprint 1

Actualizado el 12/10/2026. Candidato técnico preparado para revisión; no representa aceptación del PO ni un acuerdo nuevo entre equipos.

## Trabajo realizado

- Integradas las ramas de servidor SEM-5, contrato SEM-6, ingesta SIEM-10 y alertas SEM-20, conservando sus commits originales.
- Corregidos paquetes e imports de ingesta. Modelo adaptado a `source`, `title` y `details`.
- POST /events devuelve 200 para eventos válidos y 400 para cuerpos o eventos inválidos, siguiendo lo comunicado a G3. Sin persistencia ni deduplicación.
- Tres alertas completas leídas de `mocks/alerts.json`, incluyendo escáner y valores nulos.
- Detalle de alerta con 404 y error JSON si no existe.
- README y OpenAPI alineados con el mock. Esquema local preparado sin cambiar el recurso global.
- Mensajes, validaciones y logs del código de ingesta en inglés. El log no imprime credential ni details.

## Evidencias ejecutadas

`./mvnw -B clean verify`: BUILD SUCCESS. Cinco pruebas, cero fallos, cero errores y cero omitidas. Java local 25.0.2; compilación configurada para Java 21.

Las cuatro pruebas HTTP arrancan Spring Boot en un puerto aleatorio y cubren health, POST de los tres productores y reintentos, ausencia de cada campo obligatorio, textos vacíos, source/severity/timestamp inválidos, campo antiguo desconocido, JSON mal formado, lotes y null, Content-Type incorrecto, tres alertas completas, sus detalles y 404.

La prueba existente verifica que el contexto arranca. Estas pruebas ejercitan el servidor local real; no ejecutan los servicios de G2/G3/G4/G6/G7.

Docker terminó de arrancar. La primera prueba detectó que el Dockerfile no copiaba mocks/alerts.json; se añadió COPY mocks mocks. La segunda construcción y el healthcheck pasaron con Java 21. El script smoke-test.py superó 15 comprobaciones HTTP contra el contenedor en localhost:8005. Resultado guardado en smoke-docker-result.json. CI y compose compartidos permanecen sin cambios.

El validador local de contrato comprobó tres eventos, tres alertas completas, mapeo de IP y todas las referencias OpenAPI. El recurso shared/event-schema.json continúa pendiente de acuerdo.

## Pendiente del equipo

- Revisar esta rama y ratificar respuestas, acuse, claves extra, source/severity y detalles por productor.
- Acordar el esquema compartido con sus responsables.
- Confirmar consultas GET de G6/G7 y ejecutar integración contra sus servicios.
- Acordar con G1 credenciales y permisos para las historias de acceso posteriores.
- Ejecutar el CI del repositorio sobre el PR y revisar sus resultados.
- Revisión cruzada del equipo 4, aprobación del PR y aceptación del PO.
- Confirmar objetivo, estimaciones y capacidad del sprint en Planning.

Las historias siguen En revisión. No deben cerrarse únicamente por este documento ni por sus subtareas finalizadas.

## Actualización del 12/10/2026

Incorporada la entrega SEM-10 de Claudio, commit cb0d5dd, conservando el servidor, los GET y el manejador común de errores. Añadida JsonContractConfiguration para rechazar conversiones automáticas de números y booleanos a String. Se conservan los tipos libres dentro de details.

Añadidas dos pruebas HTTP: rechazo de tipos incorrectos en los siete campos de texto y details; conservación de los tres eventos y acuses exactos. `./mvnw -o test` termina con siete pruebas, cero fallos y cero errores. El esquema y OpenAPI documentan también el rechazo de textos formados únicamente por espacios. El validador del contrato vuelve a pasar para los tres eventos y las tres alertas.

Las pruebas de esta actualización usan el servidor local integrado. No sustituyen la ejecución de los servicios externos ni la revisión y aceptación del equipo. No se ha repetido la prueba Docker histórica de 15 comprobaciones en esta actualización.
