# SEM-29 / HU12: intentos de autenticación fallidos repetidos

## Alcance acordado

HU12 solo dispone del título «Detectar intentos de autenticación fallidos repetidos». La interpretación acordada con el equipo es reconocer y evaluar las detecciones que IDS entrega **ya agrupadas y finalizadas**. SEM-29 no vuelve a contar sus intentos, no evalúa de nuevo el umbral de IDS y no añade una ventana temporal propia.

Esta implementación cubre esa interpretación. No demuestra una correlación adicional realizada por SIEM. Si se exigiera agrupar intentos individuales, relacionar varias detecciones o evaluar otra regla, primero habría que acordar los datos de entrada, las condiciones y la configuración necesarias. No se han inventado criterios de aceptación para esa ampliación.

## Fuentes y contrato

- [Contrato local de eventos](../contract/event-schema.json): campos comunes del evento y `details` abierto, sin propiedades internas obligatorias para P004.
- [Documentación del IDS, versión consultada](https://github.com/org-software-ciber-2627/software-ciber-2627/blob/246680cd4b2815efdaf235edad4305dc2eec714c/modules/02-ids/README.md): regla P004 y ejemplo del evento enviado al SIEM.
- [Productor P004 del IDS, misma versión](https://github.com/org-software-ciber-2627/software-ciber-2627/blob/246680cd4b2815efdaf235edad4305dc2eec714c/modules/02-ids/src/patterns/brute_force.py): agrupación, identificador y construcción de los detalles.
- [Documento de integración IDS–SIEM consultado](https://github.com/org-software-ciber-2627/software-ciber-2627/blob/4cea894960fd12a70861a8356122eb9cd066112b/modules/05-siem/docs/integracion-ids-siem.md): correspondencia del evento del productor con la recepción SIEM.

El contrato de entrada `/logs` de IDS no es el contrato de salida hacia SIEM. Tampoco se utiliza `event_type: fuerza_bruta` del ejemplo histórico de una alerta del mock como alias de `brute_force`.

El archivo de pruebas `src/test/resources/ids/p004.json` reproduce el ejemplo P004 documentado por IDS: 12 intentos, IP `122.5.240.60`, ventana de 60 segundos y tiempos de inicio y fin. Es una muestra, no una nueva definición del contrato ni un umbral oficial del SIEM. No se han modificado contratos.

## Clases y uso

`RepeatedAuthenticationFailureEvaluator` es un bean de Spring independiente del controlador HTTP. Recibe el modelo `Event` existente:

```java
Optional<RepeatedAuthenticationFailure> result = evaluator.evaluate(event);
```

1. Comprueba exactamente `source = ids`, `event_type = brute_force` y `details.rule_id = P004`. También necesita un `event_id` no vacío para conservar la identidad común obligatoria.
2. Si no puede reconocer el evento, devuelve `Optional.empty()`. No convierte eventos de escaneo ni eventos de otros productores en detecciones de autenticación.
3. Interpreta únicamente los datos pertinentes disponibles, sin modificar el evento original.
4. Devuelve un `RepeatedAuthenticationFailure`, un record inmutable. La presencia del resultado significa que se ha reconocido P004; **no implica que todos sus metadatos estén disponibles o sean utilizables**.

La validación común del evento sigue en el flujo existente de recepción. El evaluador no la sustituye y no lanza errores HTTP por los detalles de P004. El flujo HTTP de esta rama todavía no invoca el evaluador: su consumidor será la integración posterior con SEM-30.

## Resultado y coherencia

| Propiedad Java | Dato de entrada | Interpretación |
| --- | --- | --- |
| `source`, `eventId` | `source`, `event_id` | Identidad original, sin generar otro identificador. |
| `attempts` | `details.attempts` | Número entero positivo de intentos ya agrupados. No es un incremento. |
| `sourceIp` | `details.source_ip` | Texto no vacío. No se realizan consultas DNS ni se añade una nueva restricción de sintaxis IP. |
| `windowSeconds` | `details.window_seconds` | Duración entera no negativa declarada por IDS. No configura otra regla del SIEM. |
| `firstAttempt`, `lastAttempt` | `details.first_attempt`, `details.last_attempt` | Instantes UTC con `Z`, según la representación documentada del productor. |
| `issues` | Coherencia de los datos suministrados | Lista inmutable de observaciones con nombres de campo y causas fijas, sin incluir valores rechazados. |

Los cinco metadatos son `Optional`: si faltan o son nulos, permanecen ausentes, sin introducir una obligación nueva. No se inventan valores por defecto ni se infieren fechas a partir del `timestamp` general.

Si un valor suministrado tiene un tipo o contenido incoherente, su propiedad queda ausente y se añade una observación. Un recuento debe ser entero y positivo para representar intentos existentes; se admite incluso `1`, sin imponer el umbral de detección de IDS. Los números enteros se representan con `BigInteger`, sin redondear ni desbordar un `int`/`long`. Un número JSON integral como `12.0` es interpretable; cadenas como `"12"`, booleanos y fracciones no se convierten en recuentos. La ventana admite `0` sin inventar un mínimo.

Si ambos instantes son válidos pero el inicio es posterior al final, se conservan ambos y se informa de la incoherencia. No se exige que la duración total de la ráfaga sea menor que `window_seconds`: la agrupación del productor puede encadenar intentos y durar más que esa ventana. Estas comprobaciones son observaciones internas, no nuevas condiciones de aceptación HTTP.

No se copian `usernames`, contraseñas, credenciales, tokens, `service`, título, descripción ni el mapa completo de `details`. Se conservan la IP y la identidad porque son pertinentes para esta detección. El componente no escribe logs. Esta selección no supone anonimizar los campos conservados: quien consuma el resultado debe tratarlos como datos del evento.

## Reenvíos e integración posterior con SEM-30

El evaluador no mantiene estado, no almacena resultados y no publica alertas. Evaluar dos veces el mismo evento produce resultados iguales y nunca suma sus intentos. Esto **no es una garantía de una única alerta** ni una implementación de deduplicación persistente.

Se conservan `source` y `eventId` para utilizar la clave compuesta existente en SEM-25/SEM-72 cuando esas historias se integren. En esta rama todavía no están incorporados sus repositorios ni el generador de SEM-30.

La integración deberá:

1. Reutilizar la persistencia y decisión de idempotencia de SEM-25/SEM-72 en el flujo de recepción. Un reenvío idéntico no debe volver a publicar; el conflicto de contenido para la misma clave debe seguir la política del servicio existente.
2. Invocar este evaluador y entregar su resultado a SEM-30 en el punto autorizado por ese flujo. El consumidor podrá consultar los `Optional` y `issues` sin interpretar de nuevo detalles arbitrarios.
3. Reutilizar la generación y notificación de SEM-30, evitando crear una segunda alerta por el mismo evento mediante una ruta paralela.
4. Añadir pruebas conjuntas de persistencia, reenvíos, conflictos y notificación antes de afirmar que no se duplican alertas.

La documentación/código de IDS permite reconocer la ráfaga por su identificador; ese identificador no es un mecanismo de almacenamiento dentro de SEM-29. Si se recibe la misma identidad con un recuento distinto, el evaluador devuelve esa nueva instantánea sin sumarla ni decidir si reemplaza otra. El supuesto acordado aquí es recibir detecciones finalizadas; una futura entrega de actualizaciones requeriría acordar su tratamiento con la política de conflictos de persistencia.

## Pruebas

`RepeatedAuthenticationFailureEvaluatorTests` comprueba el ejemplo documentado, reconocimiento exacto, exclusión de escaneos y otros productores, ausencia de identidad o regla, metadatos ausentes/nulos, números válidos y erróneos, tiempos incoherentes, ausencia de nuevos umbrales, determinismo, reenvíos con contenido distinto y selección de datos sin modificar el evento original.

`RepeatedAuthenticationFailureIntegrationTests` comprueba la inyección del bean, recepción HTTP del ejemplo y su reenvío, acuse actual intacto, lista de alertas del mock sin cambios, detalles incompletos sin nuevos HTTP 400, compatibilidad con Honeypot/Scanner y rechazo de Identity. La evaluación se invoca explícitamente en las pruebas: no se presenta como una conexión HTTP–SEM-30 ya implementada.

Las pruebas anteriores del SIEM se conservan sin cambios. Desde `modules/05-siem`:

```bash
env JAVA_HOME=/usr/lib/jvm/java-21-openjdk ./mvnw clean test
```
