Contrato de integración IDS–SIEM

1. Objetivo

El objetivo de esta integración es establecer el formato de los eventos de seguridad que el módulo 02-IDS enviará al módulo 05-SIEM, así como definir el mecanismo de comunicación entre ambos módulos. De esta manera, el SIEM podrá recibir los eventos detectados por el IDS, validarlos, procesarlos y generar las alertas correspondientes.

2. Comunicación entre módulos

La comunicación entre el IDS y el SIEM se realizará mediante peticiones HTTP utilizando el método POST. El IDS enviará los eventos en formato JSON al endpoint /events del SIEM, indicando Content-Type: application/json.

Cuando ambos módulos se ejecuten mediante Docker Compose, la dirección utilizada será http://siem:80/events. Si el SIEM se ejecuta localmente y está disponible en el puerto 8005, la dirección será http://localhost:8005/events.

Actualmente, el IDS todavía no realiza el envío automático de eventos al SIEM. Esta funcionalidad está prevista en la historia IDS-52 del Sprint 3. Mientras tanto, se podrán realizar pruebas enviando manualmente los eventos generados por el IDS.

3. Formato de los eventos

Los eventos enviados por el IDS deberán cumplir el esquema común definido en modules/05-siem/contract/event-schema.json.

Cada evento contendrá ocho campos obligatorios: event_id, que identifica de forma única el evento; timestamp, que indica la fecha y hora en formato UTC terminado en Z; source, que identifica el módulo de origen y tendrá el valor ids; event_type, que indica el tipo de ataque detectado; severity, que representa su gravedad; title, que proporciona un título descriptivo; description, que explica la detección; y details, que contiene información adicional específica del ataque.

Los valores permitidos para severity son low, medium, high y critical. El campo details será un objeto JSON cuyo contenido dependerá del patrón de detección utilizado por el IDS.

4. Tipos de eventos del IDS

Actualmente, el módulo IDS tiene implementados dos patrones de detección: fuerza bruta (P004) y escaneo de endpoints (P005).

El patrón P004 detecta ataques de fuerza bruta y password spraying. Su configuración actual identifica cinco intentos fallidos de autenticación dentro de una ventana de 60 segundos. El evento generado utiliza event_type = brute_force y puede presentar severidad medium, high o critical, dependiendo de las características del ataque. Dentro de details se incluyen datos como la dirección IP de origen, el servicio atacado, el número de intentos, los usuarios afectados y los tiempos de detección.

Por otro lado, el patrón P005 detecta conexiones hacia diferentes direcciones IP de destino dentro de una ventana temporal. El evento generado utiliza event_type = endpoint_scan y contiene información como la dirección IP de origen, las direcciones IP de destino, los puertos utilizados y el número de conexiones.

Es importante distinguir este patrón de un escaneo de puertos TCP. El IDS actualmente detecta escaneos de endpoints, por lo que el SIEM deberá aceptar el tipo endpoint_scan y conservar la lista de direcciones de destino dentro del campo details, sin exigir un único target_ip.

5. Procesamiento de eventos en el SIEM

Cuando el SIEM reciba una petición POST en /events, el controlador comprobará que el evento recibido cumple el formato establecido y que contiene los campos obligatorios.

Si el evento es válido, será procesado mediante EventService. A continuación, AlertConverter transformará el evento en una alerta de seguridad, conservando la información original y extrayendo los datos relevantes, como la dirección IP de origen.

Posteriormente, la alerta se almacenará mediante AlertRepository y se emitirá la notificación correspondiente a través de AlertService.

En los eventos P005, al no existir una única dirección IP de destino, la información de las diferentes direcciones se conservará dentro de details.

6. Manejo de errores

El SIEM deberá responder adecuadamente tanto a las peticiones válidas como a las incorrectas.

Cuando se reciba un evento válido y se procese correctamente, el endpoint devolverá una respuesta HTTP 200 OK. Si faltan campos obligatorios, existen valores no permitidos o el JSON está mal formado, deberá devolver 400 Bad Request. Si el contenido se envía con un tipo no admitido, deberá devolver 415 Unsupported Media Type.

Estos comportamientos se comprobarán mediante pruebas de integración durante la subtarea de manejo de errores y pruebas de uso.

7. Estado actual de la integración

El equipo 02 ya ha implementado la generación de eventos correspondientes a los patrones P004 y P005. Ambos utilizan los campos establecidos en el esquema común del SIEM, por lo que son compatibles con el formato general de recepción.

Por su parte, el equipo 05 dispone del endpoint POST /events, encargado de recibir y procesar los eventos de seguridad.

Sin embargo, la comunicación automática entre ambos módulos todavía está pendiente de la implementación de IDS-52. Hasta entonces, se realizarán pruebas manuales y automatizadas utilizando eventos JSON generados por el IDS para verificar que el SIEM los recibe y procesa correctamente.

8. Acuerdos pendientes

Queda pendiente confirmar formalmente con el equipo 02 la aceptación del tipo de evento endpoint_scan, obtener un ejemplo JSON completo generado por P005 y verificar conjuntamente el comportamiento del sistema ante eventos duplicados.

Una vez completada la funcionalidad IDS-52, se realizarán pruebas de integración completas para comprobar el envío automático de eventos desde el IDS hasta el SIEM.