import util.health

from threading import Thread
from util.log_parser import parse_log_lines
from util.config_loader import config
from util.parsers import parse_rules
from util.log_storage import ParsedLogStorage


def main():
    # Start Flask application in separate process
    app = Thread(target=util.health.app.run, kwargs={"port": 80, "host": "0.0.0.0"})
    app.start()

    rules = parse_rules("config/ids.rules")

    for rule in rules:
        if rule.pattern_id == "P002":
            rule.disable()

    # Intentamos leer el fichero de logs configurado.
    # Si no existe o no se puede abrir, seguimos con una lista vacía
    # para que el IDS no se caiga al arrancar.
    try:
        with open(config['LOGFILE'], encoding='utf-8') as archivo:
            eventos = parse_log_lines(archivo)
    except FileNotFoundError:
        # Caso típico en despliegues iniciales o rutas mal configuradas.
        print(f"[ERROR] No existe el fichero de logs: {config['LOGFILE']}")
        eventos = []
    except OSError as e:
        # Cubre errores de sistema de archivos (permisos, I/O, etc.).
        print(f"[ERROR] Error leyendo {config['LOGFILE']}: {e}")
        eventos = []

    # Guardamos los eventos parseados (si hay) en el almacenamiento JSON.
    storage = ParsedLogStorage()
    storage.save_many(eventos)

    print(f"[*] Log a procesar: {config['LOGFILE']}")
    print(f"[*] Whitelist: {config['WHITELIST']}")
    print(f"[*] Reglas activas")
    for rule in rules:
        rule.print()
    print(f"[*] Eventos parseados: {len(eventos)}")
    for rule in rules:
        if rule.enabled:
            rule.run()
        else:
            print(f"---Regla {rule.pattern_id} desactivada---")

    # Wait for web application to finish
    app.join()


if __name__ == "__main__":
    main()
