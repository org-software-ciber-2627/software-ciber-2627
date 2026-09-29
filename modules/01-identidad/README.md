# Módulo 1 · Identidad y secretos

- **Equipo propietario:** `equipo-01-identidad`
- **Puerto:** `8001`

## Qué expone
Servicio transversal del que dependen los otros 7 módulos: autenticación, roles y almacén de secretos.
- `POST /auth/login`
- `GET /auth/validate` (usado por el resto de módulos para comprobar sesión y rol)
- `GET /secrets/{clave}` (solo para llamadas autenticadas como rol "servicio")

## Qué consume
Nada: es la base de la que todos los demás módulos dependen.

## Estado
Contenedor placeholder (`nginx:alpine`) que responde `GET /health`. Sustituid el `Dockerfile` por vuestra implementación real cuando esté lista.
