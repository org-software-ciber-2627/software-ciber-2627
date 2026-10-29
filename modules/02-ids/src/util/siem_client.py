import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from util.config_loader import config

# Contrato del SIEM: modules/05-siem/contract/README.md
DEFAULT_SIEM_URL = "http://siem:80/events"
EVENT_FIELDS = {"event_id", "timestamp", "source", "event_type", "severity", "title", "description", "details"}


class SiemClient:
    """Envía al SIEM los eventos generados por las reglas, uno por petición."""

    def __init__(self, url=None, path=None, timeout=5):
        # Prioridad: argumento, variable de entorno SIEM_URL, ids.conf y valor por defecto
        if url is None:
            url = os.environ.get("SIEM_URL") or config.get("SIEM_URL", [DEFAULT_SIEM_URL])[0]
        if path is None:
            path = Path(__file__).resolve().parents[2] / "output" / "sent_events.json"
        self.url = url
        self.timeout = timeout
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # event_id -> "sent" (200) o "rejected" (400/415). El SIEM no deduplica,
        # así que no se vuelve a enviar ningún evento que ya esté aquí.
        self.sent = self._load()

    def send_many(self, eventos):
        enviados = rechazados = 0
        for evento in eventos:
            if not self._is_event(evento) or evento["event_id"] in self.sent:
                continue
            try:
                estado = self._post(evento)
            except (urllib.error.URLError, OSError) as e:
                # SIEM caído o inaccesible: se reintenta en el siguiente análisis
                print(f"[ERROR] No se pudo enviar al SIEM ({self.url}): {e}")
                break
            if estado is None:
                break
            self.sent[evento["event_id"]] = estado
            if estado == "sent":
                enviados += 1
            else:
                rechazados += 1
        self._save()
        return enviados, rechazados

    def _post(self, evento):
        peticion = urllib.request.Request(
            self.url,
            data=json.dumps(evento, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(peticion, timeout=self.timeout) as respuesta:
                acuse = json.loads(respuesta.read() or b"{}")
                if acuse.get("event_id") not in (None, evento["event_id"]):
                    print(f"[WARN] El SIEM confirmó {acuse.get('event_id')} al enviar {evento['event_id']}")
                return "sent"
        except urllib.error.HTTPError as e:
            cuerpo = e.read().decode("utf-8", "replace")
            if e.code in (400, 415):
                # El evento no cumple el contrato: reintentarlo daría el mismo error
                print(f"[ERROR] El SIEM rechazó {evento['event_id']} ({e.code}): {cuerpo}")
                return "rejected"
            print(f"[ERROR] El SIEM respondió {e.code} a {evento['event_id']}: {cuerpo}")
            return None

    @staticmethod
    def _is_event(evento):
        # Las reglas que aún no generan eventos del SIEM devuelven None u otros datos
        return isinstance(evento, dict) and set(evento) == EVENT_FIELDS

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as e:
            print(f"[ERROR] No se pudo leer {self.path}: {e}")
            return {}

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.sent, f, ensure_ascii=False, indent=2)
        except OSError as e:
            print(f"[ERROR] No se pudo guardar en {self.path}: {e}")
