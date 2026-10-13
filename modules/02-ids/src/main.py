from pathlib import Path

from util.log_parser import parse_log_lines
from util.config_loader import config
from util.parsers import parse_rules


def main():
    rules = parse_rules("config/ids.rules")
    with open(config['LOGFILE']) as archivo:
        eventos = parse_log_lines(archivo)

    print(f"[*] Log a procesar: {config['LOGFILE']}")
    print(f"[*] Whitelist: {config['WHITELIST']}")
    print(f"[*] Reglas activas")
    for rule in rules:
        rule.print()
    print(f"[*] Eventos parseados: {len(eventos)}")
    for rule in rules:
        rule.run()


if __name__ == "__main__":
    main()
