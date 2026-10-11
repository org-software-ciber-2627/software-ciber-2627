# Módulo 5 · SIEM simplificado

- **Equipo propietario:** `equipo-05-siem`
- **Puerto:** `8005`

## Qué expone
Hub de correlación: ingiere eventos de IDS, Honeypot y Escáner, los correla y expone alertas priorizadas.
- `GET /alerts`
- `GET /alerts/{id}`

## Qué consume
- `POST /events` de IDS, Honeypot y Escáner (formato común de evento).

## Estado actual

Servidor base implementado con Spring Boot 4.1.1 y Java 21.

Actualmente está disponible:
- `GET /health`: comprueba que el servidor está funcionando.

Los endpoints de eventos y alertas se implementarán en las siguientes tareas.

## Ejecución local

Desde `modules/05-siem/`:

./mvnw spring-boot:run

El servidor arranca por defecto en el puerto 8080.

Para comprobar su funcionamiento:

curl http://localhost:8080/health

Respuesta esperada:

{"module":"05-siem","status":"ok"}

## Docker

El Dockerfile compila la aplicación con Java 21 y la ejecuta en el puerto interno 80.

En el monorepo, Docker Compose publica el módulo SIEM en el puerto 8005.