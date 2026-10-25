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
        logs = self.read_all()
        for evento in eventos:
            entry = dict(evento)
            entry["alert"] = alert
            entry["pattern_id"] = pattern_id
            logs.append(entry)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)

    def save(self, evento, alert=False, pattern_id=None):
        self.save_many([evento], alert=alert, pattern_id=pattern_id)

    # Consultar (IDS-78)
    def read_all(self):
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
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
        return self.read_all()[-n:]