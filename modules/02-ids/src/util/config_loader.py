from pathlib import Path

config: dict = {
    # Carga de valores por defecto hardcodeados
    "LOGFILE": "../logs/1.log",
    "WHITELIST": ["127.0.0.1", "192.168.1.0/24"]
}


def parse_config(config_path) -> dict:
    config: dict = {}
    with open(config_path, 'r') as config_file:
        for line in config_file:
            line = line.strip()
            if not line or line.startswith("#"): continue
            key, *value = line.split(",")
            config[key] = value

    return config


config.update(parse_config("config/ids.conf"))
