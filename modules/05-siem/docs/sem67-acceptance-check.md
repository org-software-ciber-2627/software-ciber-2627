# SEM-67: guion de revisión y aceptación de HU8

Guion de aceptación actualizado el 27/10/2026. El recorrido de comandos se verificó en un proyecto aislado; los [resultados de almacenamiento](sem66-storage-tests.md) describen la ejecución automatizada. Esto no acredita revisión de otro miembro, aprobación del PR, CI ni aceptación del PO.

## Preparación del revisor

1. Seguir la [guía de arranque](sem67-persistence-guide.md), con Java en perfil `persistence` y PostgreSQL disponible. Para verificar automáticamente en una base desechable, usar `scripts/test-storage.py`.
2. Si se realiza la demostración manual siguiente, usar una base de desarrollo autorizada y la misma configuración/proyecto Compose antes y después del reinicio. Los comandos se ejecutan en la terminal 2 configurada en la guía, desde la raíz del repositorio. Debe tener el mismo `SIEM_DB_PORT`, contraseña y, si se configuró, `COMPOSE_PROJECT_NAME` que la terminal 1.
3. El ejemplo añade una fila de laboratorio, sin credenciales. Comprobar primero que el ID propuesto no existe. Si existe, elegir otro y sustituirlo en todos los comandos; no borrar ni sobrescribir una fila anterior.

```bash
docker compose --env-file /dev/null exec -T siem-db psql -X -U siem -d siem -c "SELECT count(*) FROM events WHERE source = 'ids' AND event_id = 'SEM67-REVIEW-20261026-001';"
```

Resultado previo esperado: cero filas con esa clave, expresado por `count = 0`. Las variables y el proyecto Compose deben ser los de la guía, incluido `SIEM_DB_PORT` si difiere de 5433. No se necesita copiar secretos al documento ni al PR.

## Guardar un evento completo

```bash
curl -i http://127.0.0.1:8005/events \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "event_id": "SEM67-REVIEW-20261026-001",
  "timestamp": "2026-10-26T12:00:00.123456789Z",
  "source": "ids",
  "event_type": "port_scan",
  "severity": "medium",
  "title": "Persistence acceptance check",
  "description": "Development event for storage verification",
  "details": {
    "test": true,
    "nested": {"ports": [22, 443], "note": null}
  }
}
JSON
```

Resultado esperado: HTTP 200 con `status` igual a `success` y `event_id` idéntico al enviado. Un health 200 por sí solo no demuestra que el evento se haya almacenado.

Recuperar la representación completa del contrato desde SQL:

```bash
docker compose --env-file /dev/null exec -T siem-db psql -X -U siem -d siem -c "SELECT jsonb_build_object('event_id', event_id, 'timestamp', original_timestamp, 'source', source, 'event_type', event_type, 'severity', severity, 'title', title, 'description', description, 'details', details) AS event FROM events WHERE source = 'ids' AND event_id = 'SEM67-REVIEW-20261026-001';"
```

Resultado esperado: una fila con los ocho campos del ejemplo, incluido el timestamp completo, los puertos anidados y el valor nulo. El orden de las claves JSON puede variar. Guardar la salida como evidencia de laboratorio sin incluir contraseñas ni datos reales de terceros.

## Recrear el contenedor conservando el volumen

```bash
docker compose --env-file /dev/null stop siem-db
docker compose --env-file /dev/null rm -f siem-db
docker compose --env-file /dev/null --profile siem-db up -d --wait siem-db
```

Repetir la consulta anterior. Debe devolver una fila con el mismo contenido completo. Repetir después exactamente el POST del ejemplo: debe devolver 200 y seguir existiendo una sola fila para `(ids, SEM67-REVIEW-20261026-001)`.

```bash
docker compose --env-file /dev/null exec -T siem-db psql -X -U siem -d siem -c "SELECT count(*) FROM events WHERE source = 'ids' AND event_id = 'SEM67-REVIEW-20261026-001';"
```

Resultado esperado: `count = 1`. No usar `down -v`: borraría el volumen del proyecto. Esta demostración no limpia la fila de laboratorio. Para evitar añadirla al entorno de trabajo, el ejecutor SEM-66 realiza la prueba equivalente y elimina únicamente su proyecto desechable.

## Registrar el resultado y la decisión humana

| Comprobación | Evidencia que debe añadirse | Estado al preparar este documento |
| --- | --- | --- |
| Evento guardado completo | Respuesta POST y consulta JSON de laboratorio | Recorrido técnico verificado el 26/10; validación del revisor pendiente |
| Evento conservado tras recrear | Misma consulta antes/después y recuento de una fila | Recorrido técnico verificado el 26/10; validación del revisor pendiente |
| Código revisado por otro miembro | Enlace al PR, identidad del revisor y resultado real | Pendiente |
| Pruebas remotas | Enlace de ejecución y checks pertinentes correctos | Pendiente de ejecutar el workflow en el PR hacia main |
| Contrato de ingesta | Acuerdo registrado sobre reenvíos, conflictos y fallos | Pendiente de ratificación |
| Aceptación del PO | Decisión explícita de Claudio, fecha y criterios comprobados | Pendiente |

La evidencia automatizada ya disponible se detalla en [las pruebas de almacenamiento](sem66-storage-tests.md). Si una comprobación falla, registrar el resultado real en Jira y mantener la condición pendiente. No rellenar decisiones de otro miembro ni del PO en su nombre.
