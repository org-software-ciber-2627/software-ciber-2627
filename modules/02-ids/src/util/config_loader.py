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


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "ids.conf"
config.update(parse_config(DEFAULT_CONFIG_PATH))