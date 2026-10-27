# SEM-66: pruebas reproducibles de almacenamiento

Actualizado el 27/10/2026 para la rama `equipo-05-siem/SEM-25-persistencia-eventos`. Las comprobaciones locales pasaron con PostgreSQL real: 36 pruebas Java sin fallos, errores u omisiones; tres pruebas Python y 15 comprobaciones HTTP. La ejecución remota de CI sigue pendiente.

## Ejecución

Requisitos: Docker con Compose v2 en ejecución, Python 3.9 o posterior y Java 21 o posterior. La primera ejecución necesita descargar las dependencias Maven y la imagen `postgres:17-alpine`.

Desde la raíz del repositorio:

```bash
python3 modules/05-siem/scripts/test-storage.py
```

Con dependencias Maven ya descargadas:

```bash
python3 modules/05-siem/scripts/test-storage.py --offline
```

El ejecutor genera un nombre de proyecto Docker, una contraseña efímera y puertos propios. Utiliza `--env-file /dev/null`, descarta variables heredadas de Spring, SIEM y Compose y limita a `127.0.0.1` tanto el JAR de prueba como las suites HTTP. No lee `.env` ni utiliza la base de trabajo.

Hace `clean verify`, por lo que reemplaza los resultados de compilación del módulo. Al finalizar elimina únicamente los recursos de su proyecto, también si una comprobación falla. Una terminación forzada puede dejar recursos con prefijo `siem-sem66-test-`; identificar el proyecto exacto antes de limpiarlos. No borrar el volumen de trabajo.

## Cobertura

| Comprobación | Evidencia ejecutable |
| --- | --- |
| Guardar y recuperar todos los campos | Ejemplos de los tres productores, JSON anidado, nulos, Unicode válido, decimales y timestamp original |
| Rechazar eventos no almacenables | Datos inválidos o no representables devuelven 400 sin insertar; sin pérdida o sustitución de caracteres |
| Reenvíos y conflictos | Misma clave y contenido idéntico: 200 con una fila; contenido distinto: 409 sin sobrescribir; concurrencia y fuentes distintas |
| Errores de almacenamiento | Error genérico simulado y caída real: 503; recuperación posterior y reenvío correctos |
| Conservación | Recreación del contenedor con el mismo volumen y comparación de todas las columnas |
| Migración | Esquema anterior con una fila, migración 002 aplicada dos veces sin pérdida |
| Logs | Identificadores neutralizados al mostrarlos; datos privados y errores de conexión ausentes del log de ingesta |
| Scripts de comprobación | Rechazo de falsos positivos con optimización Python y de informes de éxito obsoletos |

Las tres regresiones Python se ejecutan antes de crear recursos Docker y no requieren red ni PostgreSQL. El runner exige que existan y se ejecuten las suites de repositorio, HTTP persistente y logs, sin errores ni omisiones. Un Maven ejecutado sin `SIEM_TEST_DB_URL` omite PostgreSQL y no acredita persistencia.

El resumen de éxito queda en `modules/05-siem/target/sem66/report.json`, ignorado por Git. Una invocación rechazada invalida el resumen previo. Los logs temporales se eliminan al terminar y los mensajes de fallo ocultan la contraseña efímera.

## CI y aceptación

`.github/workflows/siem-storage.yml` contiene el workflow de almacenamiento revisado con G7: Ubuntu, Java 21 y Python 3.12, permisos de repositorio de solo lectura y sin secretos del repositorio. Ejecuta el mismo script y publica únicamente el resumen de éxito. `ci/sem66-storage.workflow.yml` conserva una copia de referencia.

El workflow se ejecuta en los PR hacia `main` cuando cambian los archivos pertinentes; subir solo esta rama no acredita CI verde. La PR conjunta del equipo se prepara según el procedimiento del sprint y la aprobación corresponde a los representantes. No modifica el workflow compartido `ci.yml`.

La evidencia local se obtuvo con JDK 25.0.2 y compilación release21. Falta acreditar la ejecución remota sobre Java 21. El [guion de aceptación](sem67-acceptance-check.md) recoge la revisión de otro miembro, el contrato pendiente de ratificación y la aceptación del PO.
