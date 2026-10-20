import util.health

from threading import Thread
from util.log_parser import parse_log_lines
from util.config_loader import config
from util.parsers import parse_rules


def main():
    # Start Flask application in separate process
    app = Thread(target=util.health.app.run, kwargs={"port": 80, "host": "0.0.0.0"})
    app.start()

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

    # Wait for web application to finish
    app.join()
if __name__ == "__main__":
    main()
