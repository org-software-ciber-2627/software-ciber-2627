# Módulo 2 · IDS/NIDS ligero

- **Equipo propietario:** `equipo-02-ids`
- **Puerto:** `8002`

## Qué expone
Publica los eventos de seguridad que detecta hacia el SIEM.
- `POST /events` (hacia el SIEM, formato común de evento)
Además, la aplicación dispone de un endpoint para revisar su correcto funcionamiento
- `GET /health`

## Qué consume
Nada obligatorio (opcionalmente puede validar sesión de su panel de administración contra Identidad).

## Estado
El motor del IDS se encuentra en `src/`.
Para la configuración del IDS se dispone de un fichero `config/ids.conf` con la siguiente estructura:
```
# KEY,VALUE1,VALUE2,...
LOG_FILE,../../../logs/1.log
WHITELIST,127.0.0.1,192.168.1.0/24
SIEM_URL,http://siem:80/events
```
- `SIEM_URL`: dirección de `POST /events` del SIEM. La variable de entorno
  `SIEM_URL` tiene prioridad sobre este valor.
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

## Envío de eventos al SIEM

`util/siem_client.py` envía a `POST /events` del SIEM los eventos que generan
las reglas, uno por petición y con `Content-Type: application/json`
(`SiemClient().send_many(eventos)`). Solo envía los que tienen el formato común
del SIEM (`modules/05-siem/contract/event-schema.json`).

El SIEM no elimina duplicados, así que `output/sent_events.json` guarda los
`event_id` ya tratados y no se vuelven a enviar:

| Respuesta del SIEM | Qué hace el IDS |
|---|---|
| `200` | Marca el evento como `sent` |
| `400` / `415` | Lo marca como `rejected` y registra el error; no se reintenta |
| Sin conexión, timeout u otro código | Registra el error; se reintentará en el siguiente envío |

`main.py` todavía no llama a este cliente.

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

