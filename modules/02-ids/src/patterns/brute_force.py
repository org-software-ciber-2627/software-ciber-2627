import ipaddress
from datetime import datetime, timedelta

from util.pattern_loader import pattern
from util.pattern_base import PatternBase


@pattern("P004", "Fuerza Bruta", "Medio")
class BruteForce(PatternBase):
    def __init__(self, threshold, window, *args, **kwargs):
        super().__init__()

        # Los valores llegan como texto desde ids.rules
        self.threshold = int(threshold)
        self.window = int(window)
        self.args = args
        self.kwargs = kwargs
        # Opcional: nº de usuarios distintos a partir del cual es password spraying
        self.usernames = int(kwargs["usernames"]) if "usernames" in kwargs else None
        self.whitelist_networks = [
            ipaddress.ip_network(entry, strict=False) for entry in self.whitelist
        ]

    def run(self, eventos):
        intentos_por_ip = {}
        logins_por_ip = {}

        # Agrupamos los intentos fallidos y los logins correctos por IP
        for evento in eventos:
            ip = evento.get("source_ip")
            if ip is None or self._in_whitelist(ip):
                continue

            if evento["event_type"] == "failed_login":
                intento = (self._parse_time(evento["timestamp"]), evento.get("username"), evento.get("service"))
                intentos_por_ip.setdefault(ip, []).append(intento)
            elif evento["event_type"] == "successful_login":
                logins_por_ip.setdefault(ip, []).append(self._parse_time(evento["timestamp"]))

        detecciones = []
        for ip, intentos in intentos_por_ip.items():
            intentos.sort(key=lambda intento: intento[0])
            for inicio, fin in self._find_bursts(intentos):
                rafaga = intentos[inicio:fin + 1]
                primero = rafaga[0][0]
                ultimo = rafaga[-1][0]
                # Login correcto desde la misma IP durante o justo después de la ráfaga
                login_success = any(
                    primero <= login <= ultimo + timedelta(seconds=self.window)
                    for login in logins_por_ip.get(ip, [])
                )
                detecciones.append(self._build_event(ip, rafaga, login_success))

        print(f"--- Ejecutando {self.name} (ID: {self.pattern_id}) ---")
        print(f"    Detecciones: {len(detecciones)}")
        return detecciones

    def _build_event(self, ip, rafaga, login_success):
        # Evento con el formato común del SIEM (modules/05-siem/contract/event-schema.json)
        primero = rafaga[0][0]
        ultimo = rafaga[-1][0]
        usuarios = sorted({usuario for _, usuario, _ in rafaga if usuario})
        servicio = rafaga[0][2]

        if login_success:
            severity = "critical"
            title = "Posible acceso conseguido por fuerza bruta"
        elif self.usernames is not None and len(usuarios) >= self.usernames:
            severity = "high"
            title = "Posible ataque de password spraying"
        else:
            severity = "medium"
            title = "Posible ataque de fuerza bruta"

        description = (
            f"La IP {ip} ha realizado {len(rafaga)} intentos fallidos de login "
            f"contra {len(usuarios)} usuario(s) entre {self._utc(primero)} y {self._utc(ultimo)}."
        )
        if login_success:
            description += " Después se registró un login correcto desde la misma IP."

        return {
            # Se usa el primer intento para que el id no cambie si la ráfaga crece
            "event_id": f"IDS-{self.pattern_id}-{ip}-{primero:%Y%m%dT%H%M%SZ}",
            "timestamp": self._utc(ultimo),
            "source": "ids",
            "event_type": "brute_force",
            "severity": severity,
            "title": title,
            "description": description,
            "details": {
                "rule_id": self.pattern_id,
                "source_ip": ip,
                "service": servicio,
                "attempts": len(rafaga),
                "usernames": usuarios,
                "window_seconds": self.window,
                "first_attempt": self._utc(primero),
                "last_attempt": self._utc(ultimo),
                "login_success": login_success,
            },
        }

    def _find_bursts(self, intentos):
        # Devuelve (inicio, fin) de cada ráfaga con al menos `threshold` intentos
        # dentro de `window` segundos. Una ráfaga sigue mientras el siguiente
        # intento llegue antes de `window` segundos, así se genera una sola
        # detección por ataque y no una por cada intento.
        rafagas = []
        i = 0
        while i + self.threshold - 1 < len(intentos):
            j = i + self.threshold - 1
            if self._seconds_between(intentos[i][0], intentos[j][0]) <= self.window:
                while (j + 1 < len(intentos)
                       and self._seconds_between(intentos[j][0], intentos[j + 1][0]) <= self.window):
                    j += 1
                rafagas.append((i, j))
                i = j + 1
            else:
                i += 1
        return rafagas

    def _in_whitelist(self, ip):
        try:
            direccion = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(direccion in red for red in self.whitelist_networks)

    @staticmethod
    def _parse_time(timestamp):
        # Syslog no incluye el año, asumimos el actual
        return datetime.strptime(f"{datetime.now().year} {timestamp}", "%Y %b %d %H:%M:%S")

    @staticmethod
    def _utc(momento):
        # Los logs no traen zona horaria: se interpretan como UTC
        return momento.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def _seconds_between(inicio, fin):
        return (fin - inicio).total_seconds()

    def print(self):
        extra = f",usernames={self.usernames}" if self.usernames is not None else ""
        print(f"{self.pattern_id},{self.threshold},{self.window}{extra}")
