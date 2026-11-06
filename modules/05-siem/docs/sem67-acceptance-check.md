# Verificación manual de persistencia

Este recorrido comprueba que un evento se guarda completo y permanece disponible después de recrear el contenedor. Para ejecutarlo automáticamente en recursos desechables, usa `scripts/test-storage.py`.

## Preparación

Sigue la [guía de configuración](sem67-persistence-guide.md) y comprueba que PostgreSQL y la API con el perfil `persistence` están disponibles. Ejecuta los comandos desde la raíz del repositorio con el mismo proyecto Compose y las mismas variables de configuración usados para arrancar PostgreSQL.

El ejemplo añade una fila de laboratorio. Comprueba que el identificador no existe; si ya existe, sustitúyelo en todos los pasos por otro único. No borres ni sobrescribas filas existentes.

```bash
docker compose exec -T siem-db psql -X -U siem -d siem_bd -c "SELECT count(*) FROM events WHERE source = 'ids' AND event_id = 'GRUPO5-EVENT-001';"
```

Resultado esperado antes de la prueba: `count = 0`.

## Guardar y recuperar un evento

```bash
curl -i http://127.0.0.1:8005/events \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'JSON'
{
  "event_id": "GRUPO5-EVENT-001",
  "timestamp": "2026-10-26T12:00:00.123456789Z",
  "source": "ids",
  "event_type": "port_scan",
  "severity": "medium",
  "title": "Persistence check",
  "description": "Development event for storage verification",
  "details": {
    "test": true,
    "nested": {"ports": [22, 443], "note": null}
  }
}
JSON
```

Resultado esperado: HTTP 200 con `status` igual a `success` y el mismo `event_id`.

Consulta el evento completo en PostgreSQL:

```bash
docker compose exec -T siem-db psql -X -U siem -d siem_bd -c "SELECT jsonb_build_object('event_id', event_id, 'timestamp', original_timestamp, 'source', source, 'event_type', event_type, 'severity', severity, 'title', title, 'description', description, 'details', details) AS event FROM events WHERE source = 'ids' AND event_id = 'GRUPO5-EVENT-001';"
```

Debe aparecer una fila con los ocho campos, el timestamp original, los puertos anidados y el valor nulo. El orden de las claves JSON puede variar.

## Recrear el contenedor

```bash
docker compose stop siem-db
docker compose rm -f siem-db
docker compose --profile siem-db up -d --wait siem-db
```

Repite la consulta anterior; el contenido debe conservarse. Repite exactamente el POST y comprueba que devuelve 200 sin crear otra fila:

```bash
docker compose exec -T siem-db psql -X -U siem -d siem_bd -c "SELECT count(*) FROM events WHERE source = 'ids' AND event_id = 'GRUPO5-EVENT-001';"
```

El resultado debe ser `count = 1`. No uses `docker compose down -v`, porque elimina el volumen del proyecto. Esta prueba manual conserva la fila creada; el ejecutor SEM-66 usa recursos desechables y los limpia al terminar.
