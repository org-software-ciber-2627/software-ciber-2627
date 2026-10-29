# Pruebas aisladas de almacenamiento

El ejecutor crea recursos PostgreSQL temporales y comprueba el almacenamiento HTTP, los errores, los reenvíos y la conservación de datos al recrear el contenedor.

## Requisitos y ejecución

Requiere Docker con Compose v2, Python 3.9 o posterior y Java 21 o posterior. La primera ejecución descarga las dependencias Maven y la imagen `postgres:17-alpine`.

Desde la raíz del repositorio:

```bash
python3 modules/05-siem/scripts/test-storage.py
```

Con dependencias Maven ya descargadas:

```bash
python3 modules/05-siem/scripts/test-storage.py --offline
```

El ejecutor usa un proyecto Docker aleatorio, una contraseña efímera y puertos locales propios. No lee `.env` ni utiliza la base de datos de trabajo. Enlaza el JAR y las pruebas HTTP a loopback. Ejecuta `clean verify`, que reemplaza los resultados de compilación del módulo, y elimina los recursos de su proyecto al finalizar. Si el proceso se interrumpe a la fuerza, los recursos temporales usan el prefijo `grupo5-siem-test-`; confirma el proyecto exacto antes de limpiarlo.

## Cobertura

| Comprobación | Comportamiento comprobado |
| --- | --- |
| Almacenamiento | Los campos del evento, JSON anidado, Unicode válido, decimales y timestamp original se recuperan completos |
| Validación | Los datos no almacenables devuelven 400 sin insertar ni sustituir caracteres |
| Reenvíos | La misma clave y contenido devuelve 200 sin duplicar; contenido distinto devuelve 409 sin sobrescribir |
| Fallos | La caída o indisponibilidad del almacenamiento devuelve 503; la recuperación permite continuar |
| Histórico HU10 | Colección vacía, POST→GET, orden, límites 1/500, navegación `next`, datos antiguos, parámetros inválidos y timeout real con recuperación |
| Persistencia | Recrear el contenedor con el mismo volumen conserva las columnas y el contenido del evento |
| Migración | La migración 002 se puede aplicar más de una vez y conserva filas existentes |
| Logs | Los controles se neutralizan al mostrar identificadores y no se registran datos privados ni errores de conexión |
| Runner | Se rechazan comprobaciones Python desactivadas y resúmenes de éxito obsoletos |

Las pruebas de scripts se ejecutan antes de crear recursos Docker. El runner comprueba que las suites de repositorio, HTTP persistente y logs se ejecutan sin fallos, errores ni omisiones. Ejecutar Maven sin `SIEM_TEST_DB_URL` omite las pruebas PostgreSQL y no acredita persistencia.

El resumen se guarda en `modules/05-siem/target/sem66/report.json`, ignorado por Git. Una ejecución rechazada elimina cualquier resumen anterior. Los logs temporales se eliminan al terminar y los mensajes de error no muestran la contraseña efímera.

## Validación opcional del contrato del histórico

`--verify-contract` añade la validación de las respuestas observadas del JAR contra OpenAPI, además de ejemplos y casos negativos del esquema. Requiere instalar `scripts/requirements.txt` en el intérprete que ejecuta el runner; no se instala nada automáticamente. El [procedimiento HU10](history-events-tests.md) usa un entorno temporal fuera del repositorio.

```zsh
python3 -B modules/05-siem/scripts/test-storage.py --offline --verify-contract
```

El resumen indica `history_contract_validation: passed` y el número de respuestas comprobadas cuando se solicita esta opción. Sin ella, indica `not_requested`; no se acredita validación contractual de respuestas reales. El runner habitual y el workflow existente conservan su ejecución sin esta dependencia adicional.

La fila temporal de comprobación de migración se elimina después de verificarla para ejecutar las pruebas de colección vacía sobre la base desechable. Las pruebas solo borran sus propias filas; requieren una base dedicada, no una base de trabajo. Al finalizar, el runner elimina sus recursos Docker y termina el JAR. No detiene Docker Desktop ni elimina la imagen compartida: para una sesión local desechable, se comprueban los recursos restantes y se cierra el motor al terminar.

## Integración continua

`.github/workflows/siem-storage.yml` ejecuta el mismo runner en Ubuntu con Java 21 y Python 3.12, permisos de solo lectura y sin secretos del repositorio. Se activa en pull requests hacia `main` cuando cambian los archivos pertinentes y puede iniciarse manualmente. Un push a otra rama no inicia este workflow. `ci/sem66-storage.workflow.yml` es una copia de referencia; el archivo activo está en `.github/workflows/`.
