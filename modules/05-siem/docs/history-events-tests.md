# Histórico de eventos · Pruebas y verificación local

## Alcance y dependencias

HU10 / SEM-27 consulta la tabla de eventos de HU8 mediante JDBC. El contrato está en [history-events.md](../contract/history-events.md) y [OpenAPI](../contract/openapi.json). No necesita integración real de los productores para comprobar la consulta; las pruebas envían eventos ficticios conformes al contrato.

La base de persistencia utilizada es `cb27971d6ce59919f43bc3a824739de348ee1a16` de `equipo-05-siem/SEM-25-persistencia-eventos`. El primer incremento de HU10 es `84f43f566d57da3b5eaa4f806b61f07d34415f13`; las pruebas y documentación de SEM-99/100 completan ese incremento en la rama de historia. Para identificar la versión de cualquier nueva ejecución:

```zsh
git branch --show-current
git rev-parse HEAD
git status --short
git diff --stat
```

La historia añade acceso de lectura, servicio, controlador y paginación; hereda tabla, migraciones, ingesta, pool y mapeo de HU8. No cambia el comportamiento de POST, los productores, la infraestructura compartida ni las alertas estáticas. No incluye filtros de HU11 ni IAM.

## Procedimiento reproducible

Requiere Java 21, Python 3.9 o posterior, Docker Desktop y Compose. Docker debe estar disponible antes de lanzar el runner. La imagen es `postgres:17-alpine`; `--offline` afecta solo a Maven y presupone sus dependencias en caché. Sin esa caché, omite `--offline`.

Desde la raíz del repositorio, con un entorno Python temporal fuera del proyecto:

```zsh
(
  siem_test_env="$(mktemp -d "${TMPDIR:-/tmp}/siem-history-tests.XXXXXX")" || exit 1
  trap 'rm -rf "$siem_test_env"' EXIT
  python3 -m venv "$siem_test_env/venv" || exit 1
  "$siem_test_env/venv/bin/python3" -m pip install --no-cache-dir -r modules/05-siem/scripts/requirements.txt || exit 1
  "$siem_test_env/venv/bin/python3" -B modules/05-siem/scripts/verify-contract.py || exit 1
  "$siem_test_env/venv/bin/python3" -B modules/05-siem/scripts/test-storage.py --offline --verify-contract
)
```

No se instala PostgreSQL directamente ni se modifica Python del sistema. El runner no lee `.env`, crea credenciales efímeras y puertos de loopback, y usa una base desechable independiente de la base de trabajo. No ejecutes estas pruebas contra una base compartida o con datos de trabajo. Las suites no se configuran para ejecución paralela: las pruebas del histórico requieren una colección global vacía y borran únicamente sus propias filas.

El runner aplica y comprueba la migración sobre una fila antigua; después elimina esa fila temporal para que el histórico pueda probar una colección vacía. Al finalizar termina el JAR y elimina contenedor, red y volumen de su proyecto Docker. El proceso debe poder ejecutar sus bloques de limpieza; una terminación forzada exige comprobar y limpiar el proyecto temporal exacto.

El runner no cierra el motor Docker ni borra imágenes compartidas. Después de una sesión local, revisa que no queden recursos de prueba y detén Docker Desktop si ya no lo necesitas:

```zsh
docker ps -a --format '{{.Names}} {{.Ports}}'
docker volume ls
docker network ls
docker desktop stop --timeout 30
lsof -nP -iTCP -sTCP:LISTEN
```

No elimines recursos ajenos. La imagen se puede retirar si se descargó solo para esta prueba y no la utiliza otro entorno.

## Matriz de aceptación

| Criterio | Evidencia principal | Resultado local |
| --- | --- | --- |
| Base vacía y offset máximo seguro | `EventHistoryPostgresHttpTests.emptyDatabaseAndLargestSafeOffsetReturnEmptyPages` | 200 y los tres campos de colección vacía |
| POST → GET con contenido fiel | `followsReturnedLinksWithDateSourceAndIdentifierTieBreakers` y runner del JAR | Evento recuperado con ocho campos, timestamp y JSON anidado/decimal |
| Tres fuentes y misma identidad entre fuentes | `PersistentEventHttpTests.historyListsPersistentProducersWithStableTiesAndNoReplayRows` | Identidad compuesta conservada sin filas duplicadas por reenvío |
| Fechas distintas, empates de fuente y de identificador | `followsReturnedLinksWithDateSourceAndIdentifierTieBreakers` | Orden correcto por fecha descendente, source y event_id ascendentes |
| Seguir el enlace devuelto hasta terminar | `followsReturnedLinksWithDateSourceAndIdentifierTieBreakers` | Tres páginas con dos eventos; última página exacta sin continuación |
| Límite predeterminado y máximo con fila adicional | `maximumPageAndDefaultPageKeepTheExtraRowAvailable` | 100 por defecto; página de 500 seguida de la fila 501 |
| Menos filas que el límite y offset posterior al final | Suite PostgreSQL y runner | Página final/colección vacía con ambos campos de continuación nulos |
| Fila sin original_timestamp | `historyReadsLegacyTimestampAndPreservesNestedValues` | Fallback UTC y valores anidados conservados |
| Parámetros inválidos, duplicados, desconocidos e inyección | `rejectsInvalidQueriesWithoutChangingPersistentHistory` | 400; datos persistidos intactos |
| Inválido no almacenado y reenvío sin duplicar | Suite PostgreSQL y pruebas de ingesta heredadas | Inválido ausente y una fila por clave/contenido |
| Timeout real de lectura | `realBlockedReadTimesOutAndRecoversAfterLockRelease` | Bloqueo exclusivo, cancelación en torno al timeout JDBC, 503 genérico y recuperación tras rollback |
| Caída y recreación del contenedor | Runner sobre JAR y PostgreSQL reales | 503 durante caída y lectura idéntica al recuperar el mismo volumen |
| Contexto Servlet y cabeceras de host reenviado | `EventHistoryContextHttpTests` y `EventHistoryHttpTests` | Enlace correcto; HTTP real con repositorio de prueba, sin PostgreSQL en estos casos |
| Ausencia de perfil y errores inesperados | `SiemHttpIntegrationTests` y `EventHistoryHttpTests` | 503 sin perfil; 500 ante defecto simulado, sin detalles internos |
| SQL parametrizado y recursos | `EventHistoryJdbcTests` | SQL fijo, parámetros enlazados, timeout configurado y recursos cerrados; objetos JDBC de registro |
| Contrato de respuestas reales | Runner con `--verify-contract` | Respuestas 200/400/503, cuerpos y cabeceras coherentes con OpenAPI |
| Ejemplos y rechazos del esquema | `verify-contract.py` | Referencias y ejemplos válidos; rechaza campos ausentes/extra, enlaces externos y continuación incoherente |

El test de timeout adquiere un bloqueo de tabla exclusivamente en la base desechable y lo libera con rollback en un bloque `finally`. El rango temporal de aceptación del test no se convierte en garantía de duración total de la API.

## Resultado de la ejecución local · 29/10/2026

- 62 pruebas Java, cero fallos, errores u omisiones. Incluyen seis pruebas nuevas de histórico con HTTP y PostgreSQL reales.
- Tres regresiones Python correctas y 15 comprobaciones HTTP de humo correctas sobre el JAR.
- Validación contractual de las respuestas reales solicitada expresamente mediante `--verify-contract`.
- Verificación adicional del contrato mediante esquemas, ejemplos y casos negativos, incluyendo enlaces que intentan cambiar el origen.

El runner genera `target/sem66/report.json` y JUnit deja sus resultados en `target/surefire-reports/`. Son artefactos locales de construcción ignorados por Git. El resumen distingue `history_contract_validation: passed` de `not_requested`. El modo normal del runner conserva compatibilidad con el workflow existente y no acredita esta validación opcional si no se solicita.

## Límites e integración posterior

OFFSET no ofrece una instantánea entre peticiones: inserciones concurrentes pueden producir repeticiones u omisiones. El máximo de filas no limita bytes, y un offset grande puede ser costoso. El timeout de statement no incluye todos los tiempos de conexión, serialización o transferencia. La API no implementa IAM. Estas pruebas no acreditan integración real con G4 ni las futuras fuentes de HU20.

Los resultados descritos corresponden a una ejecución local sobre la rama de histórico. No acreditan una ejecución en CI ni la compatibilidad de una versión integrada con otros cambios. Tras integrar nuevas funcionalidades, se deben repetir las comprobaciones pertinentes sobre la versión resultante.
