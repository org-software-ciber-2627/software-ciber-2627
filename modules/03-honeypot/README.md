# Módulo 3 · Honeypot inteligente

- *Equipo propietario:* `equipo-03-honeypot` (Winnie de Pot)
- *Puerto:* `8003`

## Qué hace
Login web falso que hace de señuelo. Siempre responde "Credenciales incorrectas" y guarda cada intento (IP, hora en UTC, servicio, usuario y contraseña) en una base de datos H2.

## Qué expone
- `GET /login`: la página del login falso.
- `POST /login`: recibe el intento y lo guarda.
- `GET /health`: devuelve `{"status":"ok","module":"03-honeypot"}`.
- `POST /events` (hacia el SIEM, formato común de evento): pendiente (`HP-20`).

## Qué consume
Nada obligatorio. Para probar el envío al SIEM hay un mock en `mocks/`.

## Cómo arrancarlo
- *Con Docker* (desde la raíz del repo): `docker compose up --build honeypot` → `http://localhost:8003/login`
- *Sin Docker* (desde `modules/03-honeypot`, con Java 25 o superior): `./mvnw spring-boot:run` → `http://localhost:8080/login`
- *Pruebas:* `./mvnw test`
- *Mock del SIEM:* `java mocks/SiemMockServer.java` (escucha `POST /events` en el puerto `8081`)

## Perfil dev
La página `/attempts` (ver y borrar intentos) solo existe arrancando con
`./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`.
*Nunca* poner `SPRING_PROFILES_ACTIVE=dev` en Docker: dejaría las credenciales capturadas a la vista.

## Estado
- Hecho: login falso, registro de intentos y base de datos (`HP-5`, `HP-17`).
- En curso: `Dockerfile` propio (`HP-51`), volumen para la base de datos (`HP-50`), contrato de eventos (`HP-19`) y envío al SIEM (`HP-20`).

## Configuración de la detección de fuerza bruta

Se configura en `src/main/resources/application.properties`:

| Propiedad | Valor por defecto | Qué hace |
| --- | --- | --- |
| `honeypot.fuerza-bruta.max-intentos` | 5 | Número de intentos de una misma IP a partir del cual se considera fuerza bruta |
| `honeypot.fuerza-bruta.ventana-segundos` | 60 | Ventana de tiempo, en segundos, en la que se cuentan esos intentos |

Los intentos se cuentan por IP sumando todos los servicios señuelo. Solo cuentan los intentos con contraseña: en el FTP, los comandos `USER`, `LIST`, etc. se registran pero no suman. Se etiqueta como `fuerza_bruta` a partir del intento que supera el máximo; los anteriores no se cambian.

Al SIEM se envía como `event_type` la etiqueta guardada en el intento. Si no tiene etiqueta, se envía `intento_login` (acuerdo con el grupo 5, ver `contract/`).

## Límite de peticiones

| Propiedad | Valor por defecto | Qué hace |
| --- | --- | --- |
| `honeypot.rate-limit.max-peticiones` | 10 | Peticiones por segundo y por IP. Las de más reciben 429 y no se guardan. Tiene que ser mayor que el umbral de fuerza bruta |

## Configuración de las credenciales por defecto

También en `application.properties`:

| Propiedad | Valor | Qué hace |
| --- | --- | --- |
| `honeypot.credenciales-por-defecto` | `admin:admin,root:root,...` | Lista de credenciales típicas, en formato `usuario:contraseña` separadas por comas |

Para añadir una credencial basta con ponerla en la lista, sin tocar el código. En el login web el usuario es un correo, así que se compara lo que va antes de la @: `admin@loquesea.com` con la contraseña `admin` cuenta como `admin:admin`. Un intento que usa una de ellas se etiqueta como `credenciales_por_defecto` y se envía al SIEM con severidad `high`. Si además es fuerza bruta, gana `fuerza_bruta` (acuerdo con el grupo 5). En el FTP todavía no se comprueba, porque el usuario y la contraseña llegan en comandos distintos.
