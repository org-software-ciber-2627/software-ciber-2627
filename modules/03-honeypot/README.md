# Módulo 3 · Honeypot inteligente

- *Equipo propietario:* `equipo-03-honeypot` (Winnie de Pot)
- *Puerto:* `8003`

## Qué hace
Tres servicios señuelo: un login web falso, un SSH falso y un FTP falso. Todos rechazan siempre el acceso. Cada intento se guarda en una base de datos H2 (IP, hora en UTC, servicio, usuario y contraseña o comando), se clasifica (fuerza bruta o credenciales por defecto) y se envía al SIEM del grupo 5.

## Qué expone
- `GET /login`: la página del login falso.
- `POST /login`: recibe el intento, lo guarda y lo envía al SIEM.
- `GET /health`: devuelve `{"status":"ok","module":"03-honeypot"}`.
- SSH señuelo en el puerto `2222` y FTP señuelo en el `2121`. En Docker, los tres puertos solo se publican en `127.0.0.1`.
- Hacia el SIEM: `POST /events` con el formato común de evento (ver `contract/`).

## Qué consume
Nada obligatorio. Si el SIEM no responde, los intentos se guardan igual. Para probar el envío hay un mock en `mocks/`.

## Cómo arrancarlo
- *Con Docker* (desde la raíz del repo): `docker compose up --build honeypot` → `http://localhost:8003/login`
- *Sin Docker* (desde `modules/03-honeypot`, con Java 25 o superior): `./mvnw spring-boot:run` → `http://localhost:8080/login`
- *SSH:* `ssh -p 2222 root@localhost` · *FTP:* cualquier cliente FTP contra `localhost:2121`
- *Pruebas:* `./mvnw test`
- *Mock del SIEM:* `java mocks/SiemMockServer.java` (escucha `POST /events` en el puerto `8081`)

## Perfil dev
La página `/attempts` (ver y borrar intentos) solo existe arrancando con
`./mvnw spring-boot:run -Dspring-boot.run.profiles=dev`.
*Nunca* poner `SPRING_PROFILES_ACTIVE=dev` en Docker: dejaría las credenciales capturadas a la vista.

## Estado
- Hecho: login web, FTP y SSH señuelo (`HP-6`, `HP-2`), registro de intentos, envío al SIEM, detección de fuerza bruta (`HP-12`) y de credenciales por defecto (`HP-25`), aislamiento del contenedor (`HP-30`: puertos solo en local, sin root, red interna con el SIEM) y límites de peticiones y de recursos con resumen de rechazos (`HP-32`).
- Sprint 3: conectar con el SIEM real en Docker (`HP-21`), enviar el resumen de rechazos (`HP-86`), bloquear la salida a internet (`HP-89`) y credenciales por defecto en el FTP (`HP-90`).

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

Las peticiones rechazadas no se guardan como intentos ni se envían al SIEM. Solo se guarda un resumen en la tabla `rechazos_resumen`: una fila por IP, minuto y servicio con el número de rechazos (`HP-88`). Así un ataque de muchas peticiones no llena la BD. Enviar ese resumen al SIEM queda para el Sprint 3 (`HP-86`).

## Configuración de las credenciales por defecto

También en `application.properties`:

| Propiedad | Valor | Qué hace |
| --- | --- | --- |
| `honeypot.credenciales-por-defecto` | `admin:admin,root:root,...` | Lista de credenciales típicas, en formato `usuario:contraseña` separadas por comas |

Para añadir una credencial basta con ponerla en la lista, sin tocar el código. En el login web el usuario es un correo, así que se compara lo que va antes de la @: `admin@loquesea.com` con la contraseña `admin` cuenta como `admin:admin`. Un intento que usa una de ellas se etiqueta como `credenciales_por_defecto` y se envía al SIEM con severidad `high`. Si además es fuerza bruta, gana `fuerza_bruta` (acuerdo con el grupo 5). En el FTP todavía no se comprueba, porque el usuario y la contraseña llegan en comandos distintos.

## Plan de pruebas (Sprint 2)

Cada criterio de aceptación del sprint tiene al menos una prueba. Las automáticas se lanzan con `.\mvnw.cmd test` (Windows) o `./mvnw test` desde `modules/03-honeypot`, y la CI las pasa en cada PR (job *Honeypot Tests*). Las manuales se hacen antes de cerrar la historia, y el PO deja en Jira lo que ha comprobado.

- **Unitaria:** prueba una clase sola, con mocks.
- **Integración:** arranca Spring con la BD H2 en memoria y los servicios señuelo de verdad.
- **Manual:** con un cliente FTP o SSH, o revisando el `docker-compose.yml` y el contenedor.

En el Sprint 3 el grupo 8 hará pentesting contra el honeypot.

| Historia | Criterio | Prueba | Tipo | CI | Estado |
| --- | --- | --- | --- | --- | --- |
| HP-12 | El sexto intento de una IP en 1 minuto es `fuerza_bruta` | `FuerzaBrutaIntegracionTest`: `elSextoIntentoEsFuerzaBrutaYLosAnterioresNoCambian` y `enElFtpSoloCuentanLosComandosPass` | Integración | Sí | Hecho |
| HP-12 | Los 5 primeros conservan su tipo y no se reenvían | Mismo test y `EventoMapperTest` | Integración y unitaria | Sí | Hecho |
| HP-12 | 5 intentos o menos, o separados, no son fuerza bruta | `cincoIntentosEnUnMinutoNoSonFuerzaBruta` y `seisIntentosSeparadosMasDeUnMinutoNoSonFuerzaBruta` | Integración | Sí | Hecho |
| HP-12 | El umbral se cambia en la configuración | `FuerzaBrutaConfigTest` y `ClasificadorAtaquesServiceTest` | Unitaria | Sí | Hecho |
| HP-6 | Banner de bienvenida | `FtpHoneypotIntegrationTest` comprueba el 220 | Integración | Sí | Hecho |
| HP-6 | El acceso siempre se rechaza | Cliente FTP contra `127.0.0.1:2121`: tras USER y PASS responde 530 | Manual | No | Hecho |
| HP-6 | USER, PASS y LIST quedan registrados | `FtpHoneypotIntegrationTest` (LIST, CWD y RETR) y `FuerzaBrutaIntegracionTest` (USER y PASS) | Integración | Sí | Hecho |
| HP-6 | Nunca devuelve archivos reales | `FtpHoneypotIntegrationTest`: RETR sin login devuelve 530 | Integración | Sí | Hecho |
| HP-2 | Banner realista y pide credenciales | `ssh -p 2222 prueba@127.0.0.1`: sale `OpenSSH_8.9p1 Ubuntu` y pide contraseña | Manual | No | Hecho |
| HP-2 | Siempre rechaza y nunca da terminal | Mismo `ssh`: vuelve a pedir la contraseña | Manual | No | Hecho |
| HP-2 | Registra usuario y contraseña | `SshAttemptRecorderTest`: `unIntentoConContrasenaSeGuardaClasificado` y `unIntentoConClavePublicaNoGuardaContrasena` (`HP-67`) | Unitaria | Sí | Hecho |
| HP-2 | Los intentos SSH suman para la fuerza bruta | `SshAttemptRecorderIntegracionTest`: `elSextoIntentoSshEsFuerzaBruta` (`HP-67`) | Integración | Sí | Hecho |
| HP-2 | Usa una librería SSH existente | `pom.xml`: Apache MINA SSHD | Revisión | No | Hecho |
| HP-2 (HP-69) | La huella SSH no cambia al recrear el contenedor | `ssh-keyscan -p 2222 127.0.0.1` antes y después de `docker compose down` y `up` | Manual | No | Hecho |
| HP-25 | Una credencial de la lista se etiqueta `credenciales_por_defecto` | `ClasificadorAtaquesServiceTest` (también con correo) y `CredencialesPorDefectoIntegracionTest` | Unitaria e integración | Sí | Hecho |
| HP-25 | La lista se amplía sin cambiar el código | `CredencialesPorDefectoConfigTest` | Unitaria | Sí | Hecho |
| HP-25 | Si es fuerza bruta y credencial por defecto a la vez, prevalece `fuerza_bruta` | `ClasificadorAtaquesServiceTest`: `siAdemasEsFuerzaBrutaGanaFuerzaBruta` | Unitaria | Sí | Hecho |
| HP-30 | Solo expone los puertos señuelo y solo en el entorno | `docker compose ps`: 8003, 2121 y 2222 solo en `127.0.0.1` (PR #20) | Manual | No | Hecho |
| HP-30 | No corre como root ni ve credenciales de otros módulos | `docker compose exec honeypot id` (usuario `http`) y revisar sus variables de entorno | Manual | No | Hecho |
| HP-30 | Solo alcanza al SIEM; la conexión a otros módulos falla | `docker compose exec honeypot wget -qO- http://siem/health` funciona y lo mismo contra otro módulo falla (`HP-68`, PR #26). La salida a internet queda para el Sprint 3 (`HP-89`) | Manual | No | Hecho |
| HP-32 | Más de 10 peticiones por segundo devuelven 429 | `IpRateLimiterServiceTest`: `laPeticionOnceEnElMismoSegundoSeRechaza` (`HP-71`, PR #18) | Unitaria | Sí | Hecho |
| HP-32 | Pasan al menos 6 antes de rechazar | Mismo test: pasan 10 y la 11 se rechaza; `cadaIpTieneSuPropioLimite` | Unitaria | Sí | Hecho |
| HP-32 | Resumen de rechazos en la BD | `RechazoResumenServiceIntegracionTest`: `variosRechazosEnElMismoMinutoSonUnSoloRegistro` y `otroMinutoEsOtroRegistro` (`HP-88`) | Integración | Sí | Hecho |
| HP-32 | Límites de CPU y memoria | Revisar el compose y `docker stats` (`HP-72`, PR #22) | Manual | No | Hecho |
| HP-32 | El resto de módulos sigue funcionando | Lanzar una ráfaga y comprobar el `/health` de otros módulos (`HP-73`) | Manual | No | Hecho |
