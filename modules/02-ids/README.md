# Módulo 2 · IDS/NIDS ligero

- **Equipo propietario:** `equipo-02-ids`
- **Puerto:** `8002`

## Qué expone
Publica los eventos de seguridad que detecta hacia el SIEM.
- `POST /events` (hacia el SIEM, formato común de evento)
Además, la aplicación dispone de un endpoint para revisar su correcto funcionamiento
- `GET /health`

## Publicación al SIEM

P004 y P005 se publican por HTTP en cuanto se cierra su detección. La URL se
configura con `SIEM_URL` y usa `http://siem:80/events` dentro de Docker Compose.

Los fallos temporales se conservan en `output/pending_events.json`. Los reintentos
envían una copia profunda del evento original; no regeneran el `event_id`, el
`timestamp` ni el resto del contenido.
Un HTTP `409 EVENT_ID_CONFLICT` se registra como rechazo definitivo y se elimina
de la cola. Los timeouts, errores de conexión y respuestas `503` / `5xx` siguen
siendo fallos temporales y conservan el evento original para reintentos.

### Autenticación con Identidad (G1)

Cada `POST /events` se autentica con un JWT de la cuenta de servicio de G1. El IDS
inicia sesión en `POST {IDENTIDAD_URL}/auth/login` con
`{"username": "...", "password": "..."}` y usa el campo `token` de la respuesta
como `Authorization: Bearer <token>` al publicar en el SIEM. Los tokens duran
30 minutos; el IDS los renueva automáticamente cuando quedan 2 minutos o menos.
Ante un `401` del SIEM, invalida el token, vuelve a iniciar sesión y repite esa
petición una sola vez. Si el login falla o el segundo envío recibe `401`, el
evento queda en la cola de fallos temporales. Sin credenciales, el IDS no envía
el evento sin autenticar y lo deja en esa misma cola.

| Variable | Uso | Valor por defecto |
|---|---|---|
| `IDENTIDAD_URL` | URL base de G1 (sin `/auth/login`) | `http://identidad:80` |
| `IDS_SERVICE_USERNAME` | Usuario de servicio de G1 | `servicio` |
| `IDS_SERVICE_PASSWORD` | Contraseña de la cuenta de servicio | Sin valor; necesaria para publicar |

En Docker Compose, el nombre de usuario y la URL se pueden sobrescribir con esas
variables. `IDS_SERVICE_PASSWORD` se obtiene de `SERVICE_PASSWORD`, la misma
variable que precarga la cuenta `servicio` en G1. Configúrala en el `.env` local,
nunca en el repositorio. Al ejecutar el IDS fuera de Compose, configura
`IDS_SERVICE_PASSWORD` directamente en el entorno.

## Qué consume
Nada obligatorio (opcionalmente puede validar sesión de su panel de administración contra Identidad).

## Estado
El motor del IDS se encuentra en `src/`.
Para la configuración del IDS se dispone de un fichero `config/ids.conf` con la siguiente estructura:
```
# KEY,VALUE1,VALUE2,...
LOG_FILE,../../../logs/1.log
WHITELIST,127.0.0.1,192.168.1.0/24
```
Además, para configurar las reglas se dispone de un fichero `config/ids.rules`, que tiene la siguiente estructura:
```
# PATTERN_ID,THRESHOLD,TIME_WINDOW,ARGS...
P001,5,60
P002,20,10
P003,10,120
```

Al ejecutar `python src/main.py`, se cargan todas las reglas del fichero `config/ids.rules`.
Cada regla recibe sus parámetros, el fichero de logs y la lista de IPs
permitidas. Las reglas se leen mediante la función `parse_rules` de `util/parsers.py`, que configura los módulos de patrones devueltos por `util/pattern_loader.py`.

El módulo `util/log_parser.py` transforma cada línea válida de un archivo `.log`
en un objeto JSON. Por ejemplo:

```json
{"timestamp":"Apr 20 13:51:02","service":"sshd","event_type":"failed_login","username":"root","source_ip":"122.5.240.60","source_port":54874}
```

## CLI administrativo

El CLI se ejecuta de forma independiente al proceso principal del IDS y utiliza
`requests` para llamar a la API administrativa local.

En local, desde `modules/02-ids/src`:

```bash
export IDS_ADMIN_TOKEN="token-local"
python util/cli_manager.py
```

Con Docker, el CLI puede ejecutarse dentro del contenedor mientras el servicio
IDS sigue funcionando:

```bash
docker exec -it <contenedor-ids> sh
cd /ids/src
export IDS_ADMIN_TOKEN="token-configurado-en-el-contenedor"
python util/cli_manager.py
```

La variable `IDS_ADMIN_TOKEN` es opcional, pero cuando está definida debe
enviarse como `Authorization: Bearer <token>` para acceder a `/admin/*`.
Los endpoints administrativos aceptan únicamente conexiones desde localhost.

## Patrón P004 · Fuerza bruta

Implementado en `src/patterns/brute_force.py`. Detecta una IP que acumula
demasiados intentos de autenticación fallidos en poco tiempo.

### Configuración

En `config/ids.rules`:
```
# P004,UMBRAL,VENTANA_SEGUNDOS[,usernames=N]
P004,5,60,usernames=3
```
- `UMBRAL`: número mínimo de intentos fallidos para generar alerta.
- `VENTANA_SEGUNDOS`: tamaño de la ventana deslizante.
- `usernames` (opcional): número de usuarios distintos a partir del cual se
  considera *password spraying*. Si no se indica, nunca se asigna `high`.

### Criterio de detección

1. **Eventos que cuentan como intento fallido:** los de `event_type`
   `failed_login`. No se cuentan `invalid_user` ni
   `authentication_limit_exceeded`, porque sshd los escribe junto al
   `Failed password` del mismo intento y el intento se contaría dos veces.
2. **Agrupación:** por `source_ip`. Se descartan los eventos sin `source_ip`.
3. **Exclusiones:** se ignoran las IPs incluidas en `WHITELIST` de `ids.conf`
   (admite IPs sueltas y rangos CIDR).
4. **Condición:** se genera una alerta cuando una IP alcanza `UMBRAL` intentos
   o más dentro de una ventana de `VENTANA_SEGUNDOS`.
5. **Sin duplicados:** se emite una única alerta por IP y ráfaga de ataque, no
   una por cada intento que supere el umbral.

### Severidad

| Situación | Severidad |
|---|---|
| Se supera el umbral | `medium` |
| Se supera el umbral y se intentan `usernames` usuarios distintos o más | `high` |
| `successful_login` desde la misma IP durante la ráfaga o hasta `VENTANA_SEGUNDOS` después (posible acceso conseguido) | `critical` |

### Evento generado

`run()` devuelve una lista de eventos con el esquema común del SIEM
(`modules/05-siem/contract/event-schema.json`), uno por cada IP y ráfaga.

- `event_id`: `IDS-P004-<ip>-<primer intento>`. Usa el primer intento para que
  no cambie aunque la ráfaga crezca con logs nuevos.
- `timestamp`: último intento de la ráfaga. Los logs syslog no traen zona
  horaria ni año, así que se interpretan como UTC y del año actual.
- `title` según la severidad: `Posible ataque de fuerza bruta` (`medium`),
  `Posible ataque de password spraying` (`high`) o
  `Posible acceso conseguido por fuerza bruta` (`critical`).

```json
{
  "event_id": "IDS-P004-122.5.240.60-20260420T135010Z",
  "timestamp": "2026-04-20T13:51:02Z",
  "source": "ids",
  "event_type": "brute_force",
  "severity": "medium",
  "title": "Posible ataque de fuerza bruta",
  "description": "La IP 122.5.240.60 ha realizado 12 intentos fallidos de login contra 2 usuario(s) entre 2026-04-20T13:50:10Z y 2026-04-20T13:51:02Z.",
  "details": {
    "rule_id": "P004",
    "source_ip": "122.5.240.60",
    "service": "sshd",
    "attempts": 12,
    "usernames": ["root", "admin"],
    "window_seconds": 60,
    "first_attempt": "2026-04-20T13:50:10Z",
    "last_attempt": "2026-04-20T13:51:02Z",
    "login_success": false
  }
}
```

