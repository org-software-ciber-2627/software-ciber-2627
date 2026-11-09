import json
from pathlib import Path


class ParsedLogStorage:
    """Guarda y consulta los eventos parseados en un fichero JSON."""

    def __init__(self, path=None):
        if path is None:
            path = Path(__file__).resolve().parents[2] / "output" / "parsed_logs.json"
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # Guardar (IDS-76 y IDS-77)
    def save_many(self, eventos, alert=False, pattern_id=None):
        try:
            # Leemos el histórico actual para añadir nuevos eventos al final.
            logs = self.read_all()
            for evento in eventos:
                entry = dict(evento)
                entry["alert"] = alert
                entry["pattern_id"] = pattern_id
                logs.append(entry)

            # Sobrescribimos el JSON completo con la lista actualizada.
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(logs, f, ensure_ascii=False, indent=2)

        except OSError as e:
            # Evitamos romper el proceso principal por un fallo de disco/permisos.
            print(f"[ERROR] No se pudo guardar en {self.path}: {e}")

    def save(self, evento, alert=False, pattern_id=None):
        self.save_many([evento], alert=alert, pattern_id=pattern_id)

    # Consultar (IDS-78)
    def read_all(self):
        try:
            # Si no existe aún el fichero de salida, devolvemos lista vacía.
            if not self.path.exists():
                return []

            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)

            # Validación defensiva: esperamos una lista de eventos.
            if not isinstance(data, list):
                return []

            return data

        except FileNotFoundError:
            # Carrera poco frecuente: el archivo desaparece entre exists() y open().
            return []

        except (json.JSONDecodeError, TypeError, ValueError) as e:
            # Si el JSON está corrupto o mal formado, no propagamos excepción.
            print(f"[ERROR] JSON corrupto en {self.path}: {e}")
            return []

        except OSError as e:
            # Errores de lectura del sistema de archivos.
            print(f"[ERROR] No se pudo leer {self.path}: {e}")
            return []

    def find(self, ip=None, event_type=None, only_alerts=False):
        logs = self.read_all()
        if ip:
            logs = [l for l in logs if l.get("source_ip") == ip]
        if event_type:
            logs = [l for l in logs if l.get("event_type") == event_type]
        if only_alerts:
            logs = [l for l in logs if l.get("alert")]
        return logs

    def last(self, n=10):
        logs = self.read_all()
        return logs[-n:]