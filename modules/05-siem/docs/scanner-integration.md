# Escáner → SIEM · Integración real

## Alcance y versiones

El ejecutor `scripts/test-scanner-integration.py` utiliza una copia temporal sin cambios del Escáner en `f04a1efd16fde000ddaee16711f00de86ee91b81` y el código SIEM del checkout actual. No incorpora fuentes de otros módulos a esta rama ni modifica el Compose compartido. La [especificación de entrega](../contract/scanner-events.md) y las [pruebas sintéticas](scanner-events-tests.md) cubren aspectos distintos de esta prueba.

El objetivo es el laboratorio Heartbleed de [Vulhub](https://github.com/vulhub/vulhub/tree/master/openssl/CVE-2014-0160), imagen `vulhub/openssl:1.0.1c-with-nginx`. El perfil `vuln` de G4 ejecuta Nmap, incluido el detector [ssl-heartbleed](https://nmap.org/nsedoc/scripts/ssl-heartbleed.html). No se fabrican eventos ni XML para representar un escaneo real. El objetivo no contiene datos de trabajo ni secretos reales.

## Ejecución

Requisitos: Docker Desktop iniciado, Java 21, Python 3.9 o posterior, Maven Wrapper del módulo y la referencia Git del Escáner disponible. El objetivo requiere emulación `linux/amd64` en Apple Silicon. Se necesitan descargas de imágenes y paquetes para preparar el contenedor del Escáner; `--offline` solo afecta a Maven.

Desde la raíz del repositorio:

```zsh
git fetch origin refs/pull/27/head:refs/remotes/origin/hu6-review-pr27
export JAVA_HOME="$(/usr/libexec/java_home -v 21)"
python3 -B modules/05-siem/scripts/test-scanner-integration.py --offline
```

El ejecutor fija el commit del productor: la referencia descargada debe contenerlo. Si el productor cambia, hay que revisar la nueva versión antes de actualizar la referencia utilizada por la prueba. El tiempo máximo de cada escaneo es 600 segundos; `--scan-timeout` admite entre 30 y 900.

El runner empaqueta el SIEM con `-DskipTests`; ese paso no acredita ejecución JUnit. Las regresiones Java, migraciones y casos negativos se ejecutan por separado con `scripts/test-storage.py`, como describe la [guía de compatibilidad](scanner-events-tests.md).

## Aislamiento y recorrido

- La preparación del Escáner instala sus dependencias en un contenedor desechable. Las fuentes se extraen a una carpeta temporal externa al checkout y se montan en modo lectura.
- PostgreSQL, SIEM, Escáner, observador HTTP y objetivo se ejecutan en una red Docker interna. No se publican puertos en el host y el objetivo vulnerable no tiene acceso a Internet durante las pruebas.
- PostgreSQL usa una contraseña aleatoria y almacenamiento desechable. No se lee `.env` ni se utiliza la base de desarrollo. Se aplican los scripts SQL 001, 002, 003 y 004.
- El SIEM utiliza el perfil `persistence`. G4 escucha realmente en 8004, independientemente del `EXPOSE 80` de su Dockerfile. `SIEM_URL` apunta al observador dentro de la red.
- El observador reenvía cada petición al SIEM sin cambiar el evento y devuelve su respuesta. Permite contrastar el envío y el acuse; no añade comprobaciones de entrega a G4.

## Comprobaciones

| Prueba | Evidencia exigida |
| --- | --- |
| Inventario real con perfil `quick` | G4 genera eventos con severidad `info` |
| Vulnerabilidad real con perfil `vuln` | G4 genera un evento `cve_detected`, CVE-2014-0160, script `ssl-heartbleed` y evidencia `VULNERABLE` |
| Entrega de todos los eventos | HTTP 200, `status: success` y el mismo `event_id` |
| Persistencia | Cada evento completo coincide con la fila recuperada; se preservan `details`, nulos y timestamp original |
| Reenvío real | El evento ya generado recibe acuse y no incrementa el número de filas |
| Caída del SIEM | Se detiene su contenedor; el observador registra indisponibilidad y la base no recibe nuevas filas |
| Limpieza | Se retiran contenedores, volúmenes anónimos, red e imágenes añadidas exclusivamente por el runner |

Las consultas de verificación recuperan el conjunto de filas de la base desechable con una sentencia SQL constante; no concatenan identificadores ni valores procedentes del productor.

## Informe y límites

El informe se guarda en `target/sem96/report.json`, fuera del contenido versionado. Incluye hashes del JAR y del runner, commit del productor, identificadores de imágenes, comprobaciones y recuentos. No guarda cuerpos de eventos, direcciones del laboratorio ni contraseñas. Antes de una ejecución se elimina el informe anterior para evitar presentar un éxito obsoleto.

`passed_with_producer_limitation` significa que la recepción, el acuse y la persistencia se comprobaron, y que se reprodujo una limitación del productor. No significa que todos los criterios de entrega de G4 estén resueltos. Los errores de preparación o ejecución producen salida no nula; los fallos de limpieza quedan reflejados en el informe.

### Limitación del publicador G4

En `src/jobs.py`, `publish_events_to_siem` llama a `requests.post` sin comprobar `status_code`, el cuerpo del acuse ni su `event_id`. Además, captura `RequestException` sin registrar ni exponer el resultado. `_run_job_worker` marca el trabajo como `completed` antes de publicar los eventos.

Por tanto, un escaneo puede aparecer completado aunque el SIEM rechace o no reciba sus eventos. El observador permite demostrar el fallo externo, pero no corrige la visibilidad dentro del productor. Este comportamiento pertenece al módulo 4.

El productor debe separar el resultado del escaneo del resultado de entrega, validar HTTP y acuse, y hacer visibles rechazos y resultados inciertos sin registrar cuerpos sensibles. Si implementa reintentos, debe conservar identidad y contenido. Una pérdida de conexión puede ocurrir después de almacenar: no permite afirmar automáticamente que el evento no se guardó.

## Cierre del laboratorio

El runner intenta retirar todos sus recursos incluso ante errores o interrupción normal. No elimina recursos preexistentes ni detiene automáticamente Docker Desktop, porque podría afectar otros proyectos. Una terminación forzada con `SIGKILL` impide ejecutar la limpieza: comprueba el prefijo `sem96-` y la etiqueta `siem.sem96` de esa ejecución antes de retirar recursos.

Cuando no haya otros trabajos Docker, cierra Docker Desktop:

```zsh
docker desktop stop --timeout 30
docker info
lsof -nP -iTCP -sTCP:LISTEN
```

El cierre del daemon puede tardar. Si el cierre normal deja el backend activo, `docker desktop stop --force --timeout 30` permite completar la parada cuando no haya otros trabajos. `docker info` debe dejar de responder correctamente; contrasta los puertos con el estado anterior. Esta comprobación no exige cerrar servicios ajenos al laboratorio.

## Resultado local

Ejecución local del 01/11/2026 con Java 21, PostgreSQL 17, Nmap 7.95 y el productor fijado anteriormente:

| Comprobación | Resultado observado |
| --- | --- |
| Perfil `quick` | 4 eventos de inventario |
| Perfil `vuln` | 6 eventos en total, combinando inventario y hallazgos; incluye un evento Heartbleed confirmado por `ssl-heartbleed` |
| Entrega correcta | 10 respuestas HTTP 200 con acuse e identidad coincidente |
| PostgreSQL | 10 eventos completos conservados fielmente |
| Reenvío | Acuse correcto, sin filas adicionales |
| SIEM detenido | 4 envíos reciben HTTP 502 del observador; ninguna fila adicional |
| Estado mostrado por G4 durante el fallo de entrega | `completed`; limitación del productor reproducida |
| Regresiones del ejecutor | 5 casos nuevos y 3 existentes: 8 pruebas Python correctas |
| Limpieza del ejecutor | Sin errores; sin contenedores, volúmenes, red o imágenes añadidas restantes |

El estado del informe es `passed_with_producer_limitation`. El recorrido se repitió después de corregir los problemas detectados en la revisión estática del ejecutor: invalidación de informes anteriores, saneamiento de timeouts y continuación de la limpieza ante errores individuales. La revisión posterior no identificó defectos accionables adicionales en esas correcciones.

La recepción, el acuse y el almacenamiento del módulo 5 quedan comprobados localmente. La observabilidad de entrega dentro de G4 sigue pendiente de corregir en el productor. Esta evidencia no representa ejecución en CI, integración en `main` ni aceptación formal de la historia.


En el cierre local se verificaron cero contenedores, imágenes, volúmenes y caché de compilación antes de detener Docker Desktop. Tras detener su backend y el proceso auxiliar restante, no quedaron procesos del laboratorio ni puertos adicionales respecto al estado inicial.
