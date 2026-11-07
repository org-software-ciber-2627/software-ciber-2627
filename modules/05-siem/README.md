# Equipo 5 · SIEM · Sprint 1

Candidato de integración de SEM-5, SEM-6, SEM-10 y SEM-20. Conserva el trabajo de las cuatro ramas y añade correcciones y pruebas. Requiere revisión cruzada y aceptación del PO.

## Alcance

Servidor Java 21 y Spring Boot 4.1.1. Recibe un evento JSON por petición, valida la cabecera común y devuelve un acuse. Publica tres alertas estáticas, una por productor, conservando todos sus campos y valores nulos.

No hay persistencia, deduplicación, correlación ni autenticación real en este mock. Enviar eventos no cambia la lista de alertas. El contrato de G1 y la integración externa siguen pendientes.

## Arranque con Docker

Desde la raíz del repositorio:

```bash
docker compose up --build -d siem
docker compose ps siem
curl -f http://localhost:8005/health
```

Dirección local: `http://localhost:8005`. Entre contenedores de la red `ciberurjc`: `http://siem:80`. El Dockerfile mantiene el puerto interno 80 y el healthcheck del compose compartido.

Para detener el módulo:

```bash
docker compose stop siem
```

## Arranque local con Java

Requiere Java 21 o posterior. Desde `modules/05-siem`:

```bash
./mvnw spring-boot:run
```

El puerto local por defecto es 8005. Puede configurarse con `SERVER_PORT`. El wrapper descarga Maven y las dependencias oficiales en el primer arranque.

## API del mock

| Ruta | Resultado |
| --- | --- |
| `GET /health` | 200, `{"status":"ok","module":"05-siem"}` |
| `POST /events` | 200 y acuse si el evento es válido; 400 si el cuerpo o sus campos son inválidos; 415 para un Content-Type distinto de JSON |
| `GET /alerts` | 200, `{"alerts":[...]}` con tres ejemplos |
| `GET /alerts/{id}` | 200 con una alerta; 404 con error JSON si no existe |

Se usa el 200/400 ya comunicado a G3. El borrador anterior proponía 201/422 y deduplicación; esta rama los sustituye para el mock del Sprint 1. La ratificación del contrato entre equipos y del formato del acuse sigue pendiente.

```bash
curl -i -H 'Content-Type: application/json' --data-binary @modules/05-siem/contract/examples/grupo_3_honeypot.json http://localhost:8005/events
curl -i http://localhost:8005/alerts
curl -i http://localhost:8005/alerts/SIEM-ALERT-EJEMPLO-003
```

## Contrato y comprobaciones

- `contract/openapi.json`: interfaz del mock preparada para revisión.
- `contract/event-schema.json`: esquema local del SIEM. No sustituye el esquema global pendiente de acuerdo.
- `contract/examples/`: ejemplos G2, G3 y G4.
- `mocks/alerts.json`: fuente única de las tres alertas, incluida en el JAR.

Desde `modules/05-siem`:

```bash
./mvnw clean verify
```

Las pruebas arrancan el servidor en un puerto aleatorio y comprueban los tres productores, los campos obligatorios, valores inválidos, JSON incorrecto, los tres detalles y el error 404. No certifican servicios de otros equipos.

Consultar `docs/estado-integracion.md` para evidencias y acuerdos pendientes. La API no expone credenciales en los logs; los datos de `credential` de los ejemplos son datos ficticios de laboratorio.

Comprobación del contenedor arrancado, desde la raíz del repositorio:

```bash
python3 modules/05-siem/scripts/smoke-test.py http://localhost:8005
```

Validación del contrato local. Requiere `jsonschema>=4,<5` en un entorno Python:

```bash
python3 modules/05-siem/scripts/verify-contract.py
```
