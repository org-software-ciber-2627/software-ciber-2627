# Configuración y verificación de persistencia

Esta guía configura PostgreSQL y arranca la API con almacenamiento. Para ejecutar el conjunto reproducible de comprobaciones, consulta [las pruebas de almacenamiento](sem66-storage-tests.md).

## Elegir el modo

| Modo | Uso | Resultado de un evento válido |
| --- | --- | --- |
| Java sin perfil `persistence` | Health y alertas estáticas sin PostgreSQL | 503, no confirma almacenamiento |
| Compose actual del servicio `siem` | Arranque del contenedor sin integración PostgreSQL configurada | 503 |
| Java con perfil `persistence` y PostgreSQL disponible | Ingesta y almacenamiento reales | 200 tras guardar o reconocer un reenvío idéntico |
| Ejecutor SEM-66 | Verificar la implementación con base desechable | Comprueba guardado, errores, reenvíos y recreación del contenedor |

Requisitos: Java 21 o posterior, Docker con Compose v2 y Python 3.9 o posterior para el ejecutor. El primer arranque necesita descargar dependencias e imagen PostgreSQL.

## Comprobación automática recomendada

Desde la raíz del repositorio:

```bash
python3 modules/05-siem/scripts/test-storage.py
```

Con dependencias Maven disponibles se puede añadir `--offline`. Se crean proyecto, contraseña y puertos propios; no se lee `.env` ni se utiliza el volumen de trabajo. El script borra únicamente sus recursos aislados al terminar. Hace `clean verify`, por lo que reemplaza los resultados de compilación del módulo. Si se fuerza la terminación pueden quedar recursos con el prefijo `grupo5-siem-test-`.

Resultado esperado: todas las suites Java sin fallos, errores ni omisiones; regresiones de los scripts, migración, caída/recuperación, conservación y smoke HTTP correctas. El resumen se genera en `target/sem66/report.json` dentro del módulo. Un `./mvnw test` que omita PostgreSQL no acredita esta condición.

## Arranque manual de desarrollo

Los comandos siguientes se ejecutan desde la raíz del repositorio, salvo el bloque que cambia al directorio del módulo. El operador introduce la contraseña local ya configurada; no se escribe en el comando ni en el repositorio. Si el volumen ya existe, debe coincidir con su contraseña actual. Cambiar una variable no cambia la contraseña de una base inicializada.

En la terminal 1, zsh o bash. Si necesitas otro puerto PostgreSQL, sustituye `5433` por el mismo valor en los bloques de ambas terminales:

```bash
printf 'Local PostgreSQL password: '
read -rs SIEM_DB_PASSWORD
printf '\n'
export SIEM_DB_PASSWORD
export SIEM_DB_PORT=5433
export SIEM_DB_NAME=siem_bd
```

Para arrancar exclusivamente PostgreSQL, evitando cargar `.env`:

```bash
docker compose --env-file /dev/null --profile siem-db up -d --wait siem-db
docker compose --env-file /dev/null exec -T siem-db pg_isready -U siem -d siem_bd
docker compose --env-file /dev/null exec -T siem-db psql -X -U siem -d siem_bd -c '\d events'
```

Resultado esperado: contenedor healthy y tabla `events` con clave `(source, event_id)`, `details` JSONB y `original_timestamp`. La contraseña debe ser no vacía al inicializar un volumen nuevo. Si el volumen ya existía antes de la migración 002, respáldalo antes de aplicar cambios. El script es aditivo y repetible:

```bash
docker compose --env-file /dev/null exec -T siem-db psql -X -U siem -d siem_bd -v ON_ERROR_STOP=1 < modules/05-siem/db/init/002-add-original-timestamp.sql
```

Con un volumen nuevo, ambos scripts se aplican automáticamente. El puerto PostgreSQL se publica en `127.0.0.1:5433`; si se usa otro puerto, mantén el mismo `SIEM_DB_PORT` para Compose y Java.

Si el volumen ya contiene la base antigua `siem`, cambiar `SIEM_DB_NAME` no la renombra. Detén primero la aplicación, crea una copia de seguridad fuera del repositorio y confirma que `siem_bd` no existe y que `siem` no tiene sesiones activas. Después, desde la raíz del repositorio:

```bash
docker compose --env-file /dev/null exec -T siem-db psql -X -U siem -d postgres -c 'ALTER DATABASE siem RENAME TO siem_bd;'
```

Comprueba que `siem_bd` abre y que las filas de `events` siguen presentes antes de arrancar la aplicación. La operación conserva el volumen; no lo borres ni recrees para cambiar el nombre.

Arranca Java en esa terminal, conservando las variables anteriores:

```bash
export SERVER_PORT=8005
unset SIEM_DB_URL
cd modules/05-siem
./mvnw spring-boot:run -Dspring-boot.run.profiles=persistence -Dspring-boot.run.arguments=--server.address=127.0.0.1
```

`unset SIEM_DB_URL` selecciona la conexión local por defecto. En esta receta no se reutiliza una URL de otro entorno. Detén previamente cualquier servidor que ocupe el puerto 8005. La aplicación Java no carga por sí misma el `.env` de Compose. Para un arranque limpio, evita valores heredados de `SPRING_*` que cambien perfiles o fuentes de configuración.

| Variable | Valor o función en este arranque |
| --- | --- |
| `SIEM_DB_PASSWORD` | Contraseña local, introducida sin eco; nunca versionarla |
| `SIEM_DB_PORT` | 5433 por defecto |
| `SIEM_DB_NAME` | `siem_bd` por defecto |
| `SIEM_DB_URL` | Opcional; en este ejemplo se elimina para usar `jdbc:postgresql://127.0.0.1:<puerto>/siem_bd` |
| `SERVER_PORT` | 8005 por defecto |
| Usuario PostgreSQL | `siem`, definido en la configuración |

En la terminal 2, situada en la raíz del mismo repositorio, vuelve a configurar el puerto y la contraseña. Las variables exportadas en la terminal 1 no se transmiten a una terminal nueva. Si has definido `COMPOSE_PROJECT_NAME` para elegir un proyecto, exporta exactamente el mismo valor también aquí; no elijas otro proyecto para el reinicio.

```bash
export SIEM_DB_PORT=5433
export SIEM_DB_NAME=siem_bd
printf 'Same local PostgreSQL password as terminal 1: '
read -rs SIEM_DB_PASSWORD
printf '\n'
export SIEM_DB_PASSWORD
```

Mantén esta terminal abierta para la comprobación y el reinicio. Con la API de la terminal 1 disponible:

```bash
curl -f http://127.0.0.1:8005/health
python3 modules/05-siem/scripts/smoke-test.py http://127.0.0.1:8005
```

El smoke inserta los ejemplos de laboratorio en la base seleccionada; úsalo en un entorno de desarrollo. Se puede repetir si esos identificadores conservan el mismo contenido. No limpia esas filas. Para comprobar persistencia sin añadir datos al volumen de trabajo, utiliza el ejecutor SEM-66.

## Qué se conserva y qué respuesta esperar

Los ocho campos del contrato son `event_id`, `timestamp`, `source`, `event_type`, `severity`, `title`, `description` y `details`. La tabla guarda el instante como `occurred_at` y el texto completo como `original_timestamp`, además de los restantes campos. `details` conserva objetos JSON anidados.

| Petición | Resultado implementado |
| --- | --- |
| Evento válido nuevo | 200 después de almacenar |
| Mismo `(source, event_id)` y contenido equivalente | 200, una fila |
| Misma clave con otro contenido | 409 `EVENT_ID_CONFLICT`, original intacto |
| Evento inválido | 400, sin nueva fila |
| Tipo de contenido no admitido | 415 |
| Sin almacenamiento configurado o caída durante ingesta | 503 `STORAGE_UNAVAILABLE` |

Con persistencia activa se rechazan con 400 los textos con caracteres nulos o Unicode incompleto, también dentro de `details`, y las fechas o números fuera del rango de almacenamiento. Se conserva el error genérico: no se devuelven SQL ni datos de conexión. Los fallos reales de PostgreSQL continúan produciendo 503. El Unicode válido, incluidos caracteres suplementarios, se guarda y reenvía sin sustituciones.

Si PostgreSQL no está disponible al arrancar con `persistence`, la creación del pool puede impedir el arranque; no debe confundirse con un servidor arrancado que responde 503. El [comportamiento de ingesta](../contract/sem65-ingestion-proposal.md) describe 409 y 503; el OpenAPI histórico conserva las respuestas del mock anterior.

La clave incluye `source`: el mismo ID de dos productores ocupa dos filas. Los reenvíos se comparan sin sobrescribir el evento. Los logs escapan controles y separadores solo al mostrarlos; el identificador original se conserva en almacenamiento y recibo.

## Reinicio y diagnóstico

En la terminal 2 ya configurada, desde la raíz del repositorio, para parar o recrear el contenedor conservando datos:

```bash
docker compose --env-file /dev/null stop siem-db
docker compose --env-file /dev/null rm -f siem-db
docker compose --env-file /dev/null --profile siem-db up -d --wait siem-db
```

Esto conserva el volumen nombrado del mismo proyecto. No uses `down -v` ni borres el volumen de trabajo. Mantén el mismo directorio/proyecto Compose. La comparación automatizada SEM-66 verifica todas las columnas antes y después de recrear su propio contenedor.

| Síntoma | Comprobar |
| --- | --- |
| 503 con Java sin perfil | Activar `persistence` y proporcionar la configuración |
| Error de autenticación PostgreSQL | Contraseña del volumen existente, sin imprimirla en logs |
| Falta `original_timestamp` | Aplica la migración 002 al volumen existente |
| Puerto ocupado | Otro proceso o contenedor en 8005/5433; no detener procesos ajenos automáticamente |
| 409 al repetir un ejemplo | El contenido guardado para esa clave difiere; no borrar datos para forzar 200 |
| Pruebas PostgreSQL omitidas | Usar el ejecutor SEM-66 o una base exclusiva de pruebas configurada |

La ingesta aún no autentica productores. El arranque de esta guía se limita a loopback; la exposición compartida necesita acordar controles de acceso. Las alertas siguen siendo ejemplos estáticos y no cambian al insertar eventos.

Para comprobar manualmente el guardado completo y la conservación, sigue [la verificación de persistencia](sem67-acceptance-check.md).
