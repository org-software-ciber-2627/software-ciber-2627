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
en un objeto JSON. `main.py` lee temporalmente `logs/1.log` según la ruta de
`ids.conf` y le pasa sus líneas al parser. Los eventos quedan en memoria y no
se escriben en otro archivo ni se envían a las reglas todavía. Por ejemplo:

```json
{"timestamp":"Apr 20 13:51:02","service":"sshd","event_type":"failed_login","username":"root","source_ip":"122.5.240.60","source_port":54874}
```
