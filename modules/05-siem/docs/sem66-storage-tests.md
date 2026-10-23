# SEM-66: pruebas reproducibles de almacenamiento

Estado a 23/10/2026: verificación local correcta en la rama `equipo-05-siem/SEM-25-persistencia-eventos`. Sin commit ni publicación de estos cambios. SEM-66 sigue En curso porque falta integrar la propuesta con G7 y ejecutar el pipeline remoto.

## Ejecución

Requisitos: Docker con Compose v2 en ejecución, Python 3.9 o posterior y Java 21 o posterior. La primera ejecución necesita acceso a los repositorios de Maven y a la imagen `postgres:17-alpine`.

Desde la raíz del repositorio:

```bash
python3 modules/05-siem/scripts/test-storage.py
```

Si las dependencias de Maven ya están disponibles en el equipo:

```bash
python3 modules/05-siem/scripts/test-storage.py --offline
```

El script utiliza un proyecto Docker con nombre aleatorio, una contraseña efímera generada en memoria y puertos locales libres. Pasa `--env-file /dev/null`, descarta variables heredadas de Spring, SIEM y Compose, y enlaza la API de prueba a `127.0.0.1`. No utiliza la base de datos de trabajo ni lee `.env`. Al finalizar, elimina únicamente el contenedor, red y volumen de su propio proyecto, también si una comprobación falla. Si se interrumpe con una terminación forzada del proceso, puede ser necesaria una limpieza manual del proyecto identificado con el prefijo `siem-sem66-test-`.

La ejecución hace `clean verify`, por lo que reemplaza los resultados de compilación anteriores del módulo. Los logs temporales se eliminan al terminar. Si Maven falla, se muestra el final del log ocultando la contraseña efímera. El informe resumido de éxito queda en `modules/05-siem/target/sem66/report.json`, ignorado por Git. Un fallo elimina el informe previo y devuelve un estado de error.

## Qué comprueba

| Condición de SEM-66 | Evidencia ejecutable |
| --- | --- |
| Guardar y recuperar el evento completo, incluido `details` | `PostgresEventRepositoryTests` y `PersistentEventHttpTests`, con los tres ejemplos de productor, JSON anidado, nulos, Unicode, precisión decimal y timestamp original |
| No guardar eventos inválidos | `PersistentEventHttpTests.rejectsInvalidEventsBeforePersisting` comprueba 400 y cero filas para sus identificadores |
| Duplicados y conflictos | Reenvíos idénticos, cambios en cada campo, mismo ID en fuentes distintas y concurrencia; una sola fila por clave y sin sobrescritura |
| Fallos de almacenamiento | Error simulado con respuesta genérica y caída real de PostgreSQL desde el JAR empaquetado: 503; recuperación: 200 al reenviar y 409 al cambiar el contenido |
| Conservación al reiniciar | Se detiene y elimina solo el contenedor de prueba; se recrea con el mismo volumen y se comparan todas las columnas de la fila antes y después |
| Migración compatible | Se crea el esquema anterior, se inserta una fila y se aplica dos veces la migración 002, conservando la fila |
| Pipeline verde | Pendiente de revisión con G7, publicación autorizada y ejecución remota |

El ejecutor rechaza resultados con fallos, errores o pruebas omitidas. También exige que existan y se ejecuten las suites de repositorio, HTTP persistente y logs. Un `./mvnw test` sin `SIEM_TEST_DB_URL` omite las suites PostgreSQL y no sustituye esta comprobación.

## Corrección de logs asociada

`EventService` convierte los controles ISO, incluidos CR, LF, NEL y ESC, y los separadores Unicode U+2028/U+2029 en secuencias visibles únicamente al escribir `event_id` en los logs de confirmación y error. El evento, su clave, su respuesta HTTP y las validaciones se mantienen intactos.

Se reprodujo el problema antes de corregirlo: tres pruebas de logs, dos fallos por caracteres sin escapar y una prueba Unicode ordinaria correcta. Después, las tres pasan. Se cubren inserción, reenvío y fallo de almacenamiento, sin registrar el contenido privado ni la excepción de base de datos. La prueba HTTP adicional comprueba que el identificador original con separadores sigue aceptándose, almacenándose y reenviándose sin duplicar filas.

## Resultado local

Ejecución del 23/10/2026 con `python3 modules/05-siem/scripts/test-storage.py --offline`:

- Java: 31 pruebas, cero fallos, errores u omisiones; compilación y empaquetado correctos.
- JAR: caída real 503, recreación del contenedor conservando toda la fila, reenvío 200 y conflicto 409.
- Smoke HTTP: 15 comprobaciones correctas.
- Migración repetible y limpieza del proyecto aislado correctas.
- Revisión independiente del cambio de logs y del aislamiento del ejecutor sin incidencias concretas.

Entorno local: JDK 25.0.2, compilación Java release 21. Esto no acredita todavía ejecución sobre JDK 21 ni GitHub Actions.

## Propuesta para CI

`ci/sem66-storage.workflow.yml` contiene un workflow propuesto para revisión de G7. Todavía no está en `.github/workflows/` y no se ejecuta automáticamente. Propone Ubuntu, Java 21 y Python 3.12; ejecuta el mismo script y conserva solo el resumen de éxito. No requiere secretos del repositorio.

Tras coordinarlo con G7, el destino propuesto es `.github/workflows/siem-storage.yml`. No modifica el workflow compartido existente. Solo una ejecución remota correcta permitirá acreditar la última condición de SEM-66. La validación de Darío, el contrato compartido, Dockerfile y la autenticación quedan fuera de estos cambios.
