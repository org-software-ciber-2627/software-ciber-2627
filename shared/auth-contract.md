# Contrato de autenticación (Identidad y secretos)

El equipo `equipo-01-identidad` publica aquí, en el Sprint 1, el contrato exacto de los 3 endpoints que expone. Hasta entonces, los cuerpos de petición/respuesta se marcan como **pendientes**.

## Endpoints

### `POST /auth/login`
- **Request:** _pendiente (lo publica Identidad)_
- **Response:** _pendiente (lo publica Identidad)_

### `GET /auth/validate`
- **Request:** _pendiente (lo publica Identidad)_
- **Response:** _pendiente (lo publica Identidad)_

### `GET /secrets/{clave}`
- **Request:** _pendiente (lo publica Identidad)_
- **Response:** _pendiente (lo publica Identidad)_
- Solo para llamadas autenticadas como rol "servicio".

## Roles
- `admin`
- `analista`
- `servicio`
