# Escáner → SIEM · Pruebas de compatibilidad

## Alcance

Estas pruebas verifican la recepción y persistencia del SIEM con eventos sintéticos del formato del Escáner. No ejecutan el Escáner ni Nmap y no acreditan una entrega real del productor. El contrato se describe en [scanner-events.md](../contract/scanner-events.md).

La extensión se aplica sobre la persistencia de HU8, referencia `cb27971d6ce59919f43bc3a824739de348ee1a16`. Esta rama no incluye la implementación del histórico de HU10. El soporte de `info` afecta al catálogo común de eventos, no al catálogo público de alertas.

## Ejecución reproducible

Requiere Docker Desktop con Compose, Java 21 y Python 3.9 o posterior. El runner utiliza PostgreSQL `17-alpine` en un proyecto aleatorio y no lee `.env` ni usa la base de trabajo. `--offline` solo afecta a Maven; omítelo si faltan sus dependencias en caché.

Desde la raíz del repositorio, el siguiente bloque valida contratos con un entorno Python temporal y ejecuta las pruebas:

```zsh
(
  siem_test_env="$(mktemp -d "${TMPDIR:-/tmp}/siem-scanner-tests.XXXXXX")" || exit 1
  trap 'rm -rf "$siem_test_env"' EXIT
  python3 -m venv "$siem_test_env/venv" || exit 1
  "$siem_test_env/venv/bin/python3" -m pip install --no-cache-dir -r modules/05-siem/scripts/requirements.txt || exit 1
  "$siem_test_env/venv/bin/python3" -B modules/05-siem/scripts/verify-contract.py || exit 1
  "$siem_test_env/venv/bin/python3" -B modules/05-siem/scripts/test-storage.py --offline
)
```

No instales PostgreSQL directamente para ejecutar el laboratorio. Las contraseñas de pruebas se generan de forma efímera. El runner termina el JAR y elimina contenedores, volumen y red de su proyecto al finalizar. Si se interrumpe a la fuerza, comprueba los recursos del proyecto exacto antes de retirarlos. No elimina imágenes compartidas ni detiene Docker Desktop; revisa los recursos restantes y cierra el motor cuando ya no se necesite. No elimines recursos de otros proyectos.

## Matriz de comprobación

| Caso | Evidencia | Resultado |
| --- | --- | --- |
| `service_detected` y `port_open` con `info` | `ScannerEventHttpTests.storesInformationalScannerEventsWithFaithfulFieldsAndNoNewAlerts` | 200 con acuse, contenido recuperado fielmente y sin nuevas alertas |
| Cinco severidades en los tres orígenes actuales | `acceptsTheCommonSeverityCatalogForEveryExistingSource` | Todas admitidas sin reglas especiales por productor |
| Formato antiguo y tipos inválidos | `rejectsLegacyScannerShapeInvalidSeveritiesDatesAndReportsWithoutStorage` | 400 ante source antiguo, target raíz, severidades inválidas, fechas incorrectas e informes/arrays |
| Reenvío idéntico | Suite HTTP y runner del JAR | 200 y una sola fila por identidad |
| Cambiar `info` a `low` con la misma identidad | `changingInfoToLowIsAConflictAndCannotOverwriteTheOriginalEvent` | 409 y evento informativo original intacto |
| Restricción SQL independiente de HTTP | `PostgresEventRepositoryTests.databaseAcceptsInfoAndStillRejectsUnknownSeverityWhenHttpValidationIsBypassed` | `info` se almacena y una severidad desconocida falla sin insertar |
| Sin perfil de persistencia | `SiemHttpIntegrationTests` | Un evento informativo válido responde 503; no éxito aparente |
| Base antigua antes de migrar | Runner con fixture SQL de cuatro severidades | `info` rechazado por `events_severity_check` |
| Migración y reaplicación | Runner y `003-allow-info-severity.sql` | `info` admitido, filas anteriores e informativas conservadas y valores desconocidos rechazados |
| Instalación nueva | Runner con 001, 002 y 003 en esquema desechable | `info` admitido desde cero |
| Caída y recuperación de PostgreSQL | Runner del JAR | 503 durante caída; datos conservados al recrear el contenedor y reenvíos correctos |
| Catálogos y ejemplos públicos | `verify-contract.py` | Cuatro ejemplos de eventos válidos; Alert conserva cuatro severidades; valores inválidos rechazados por ambos esquemas |

El fixture `src/test/resources/db/legacy-events-before-info.sql` conserva la definición anterior de HU8 únicamente para reproducir la actualización. La tabla de producción se define en `db/init/001-create-events.sql`; el fixture no se aplica a una base de trabajo.

## Resultado local

- 41 pruebas Java ejecutadas, cero fallos, errores u omisiones; PostgreSQL habilitado.
- Ocho regresiones Python correctas, incluidas cinco de seguridad y limpieza del ejecutor de integración real.
- 16 comprobaciones HTTP de humo correctas contra la aplicación empaquetada.
- Contratos, referencias y cuatro ejemplos de eventos validados; el catálogo de alertas conserva sus valores anteriores.
- Migración desde el esquema antiguo, reaplicación, conservación de datos e instalación nueva correctas.

Los resultados de JUnit están en `target/surefire-reports/`; el runner genera `target/sem66/report.json`, ignorado por Git. Estos resultados corresponden a esta rama de persistencia y compatibilidad, no a la suite de histórico ni a una ejecución de CI.

## Límites

Las pruebas de compatibilidad envían JSON preparado. Para acreditar la integración real se necesita un evento generado por el Escáner, su acuse correlacionado por `event_id`, comprobación de almacenamiento y un fallo de entrega observable. La versión de publicador referenciada en el contrato todavía ignora respuestas y excepciones de envío; estas pruebas no modifican ni validan ese comportamiento.

La API no implementa autenticación ni autorización de productores y se usa HTTP sin TLS en el laboratorio. Los eventos sintéticos no contienen secretos reales; la conexión a PostgreSQL sí utiliza su contraseña externa. La ampliación no añade reintentos automáticos, correlación, generación de alertas ni cambios en otros módulos.


El recorrido ejecutando el productor real se documenta por separado en [scanner-integration.md](scanner-integration.md); sus resultados no se deducen de estas pruebas sintéticas.
