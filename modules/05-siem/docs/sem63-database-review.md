# SEM-63: revisión local de la base de datos

Fecha: 20 de octubre de 2026.

## Estado

Revisión técnica local realizada. Pendiente de revisión de JC, revisión por otro miembro del equipo y aceptación del PO. Este informe no acredita integración con la aplicación Java, CI ni publicación de las correcciones.

Rama local: `equipo-05-siem`. No se ha sincronizado con GitHub durante esta revisión. La copia del checkout anterior se ha mantenido sin cambios. Ningún Dockerfile ha sido modificado.

## Fallos encontrados y corregidos

- El compose general exigía `SIEM_DB_PASSWORD` incluso con `siem-db` desactivado. Se ha eliminado esa exigencia durante la interpolación; PostgreSQL continúa rechazando la inicialización sin contraseña.
- La clave primaria global `event_id` contradecía el contrato, que establece identificadores únicos dentro de cada `source`. Ahora se utiliza `(source, event_id)`.
- Los controles basados en `btrim` aceptaban tabulaciones y saltos de línea sin contenido. Ahora los textos obligatorios requieren un carácter no blanco.
- Se ha documentado que el SQL inicial se aplica solo a volúmenes vacíos y no migra datos ya existentes.

## Evidencia

La revisión utilizó PostgreSQL 17 en proyectos Docker temporales, con nombres, credenciales, puertos y volúmenes independientes. Se eliminaron únicamente sus recursos de prueba al finalizar.

Antes de corregir el esquema: 34 comprobaciones correctas y 5 fallidas. Se reprodujeron el rechazo del identificador compartido entre productores y la aceptación de cuatro campos formados solo por tabulación y salto de línea.

Después de corregir el esquema: **39 comprobaciones correctas y 0 fallidas**.

Se verificaron:

- Arranque saludable y creación automática de `events`.
- Compatibilidad del compose general sin contraseña cuando no se activa la base de datos.
- Publicación del puerto exclusivamente en la interfaz local.
- Inserción y recuperación completa de los tres ejemplos JSON del contrato.
- Conservación de objetos, listas, booleanos, valores nulos y texto Unicode dentro de `details`.
- Rechazo de duplicados del mismo productor y aceptación del mismo identificador en productores distintos.
- Rechazo de `source`, `severity` y tipos de `details` no admitidos.
- Rechazo de los ocho campos obligatorios nulos y de textos vacíos o compuestos solo por espacios, tabulaciones o saltos de línea.
- Reaplicación del SQL sin pérdida de datos, sobre la misma versión del esquema.
- Conservación de filas y `details` tras eliminar y recrear únicamente el contenedor.
- Limpieza de los recursos temporales de prueba.

Además, se comprobó con el compose real que inicializar una base de datos nueva sin contraseña falla con el mensaje de contraseña de superusuario no especificada. Se eliminaron también los recursos aislados de esa comprobación.

Estas pruebas usan acceso SQL directo. La recepción persistente mediante `POST /events` corresponde a las subtareas posteriores de HU8.
