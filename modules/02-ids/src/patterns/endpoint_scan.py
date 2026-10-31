import ipaddress
from datetime import datetime

from util.pattern_loader import pattern
from util.pattern_base import PatternBase


@pattern("P005", "Escaneo de Endpoints", "Medio")
class EndpointScan(PatternBase):

    def __init__(self, threshold, window, *args, **kwargs):
        super().__init__()

        # Los valores llegan como texto desde ids.rules
        # threshold = nº mínimo de endpoints distintos
        # window = ventana temporal en segundos
        self.threshold = int(threshold)
        self.window = int(window)
        self.args = args
        self.kwargs = kwargs

        self.whitelist_networks = [
            ipaddress.ip_network(entry, strict=False) for entry in self.whitelist
        ]

    def run(self, eventos):
        # {"192.168.1.50": [(timestamp, destino, puerto), ...]}
        conexiones_por_ip = {}

        for evento in eventos:
            source_ip = evento.get("source_ip")
            destination_ip = evento.get("destination_ip")

            if source_ip is None or destination_ip is None:
                continue
            if self._in_whitelist(source_ip):
                continue

            conexion = (
                self._parse_time(evento["timestamp"]),
                destination_ip,
                evento.get("destination_port"),
            )
            conexiones_por_ip.setdefault(source_ip, []).append(conexion)

        detecciones = []
        for ip, conexiones in conexiones_por_ip.items():
            conexiones.sort(key=lambda conexion: conexion[0])
            for inicio, fin in self._find_scans(conexiones):
                ventana = conexiones[inicio:fin + 1]
                detecciones.append(self._build_event(ip, ventana))

        print(f"--- Ejecutando {self.name} (ID: {self.pattern_id}) ---")
        print(f"    Detecciones: {len(detecciones)}")
        return detecciones

    def _build_event(self, ip, ventana):
        # Evento con el formato común del SIEM
        primero = ventana[0][0]
        ultimo = ventana[-1][0]
        endpoints = sorted({destino for _, destino, _ in ventana})
        puertos = sorted({puerto for _, _, puerto in ventana if puerto is not None})

        # Severidad: medium por defecto; high si el escaneo es muy amplio
        # (el doble del umbral o más)
        if len(endpoints) >= 2 * self.threshold:
            severity = "high"
        else:
            severity = "medium"

        description = (
            f"La IP {ip} ha contactado con {len(endpoints)} endpoints distintos "
            f"({len(ventana)} conexiones) entre {self._utc(primero)} y {self._utc(ultimo)}."
        )

        return {
            # Se usa la primera conexión para que el id no cambie si el escaneo crece
            "event_id": f"IDS-{self.pattern_id}-{ip}-{primero:%Y%m%dT%H%M%SZ}",
            "timestamp": self._utc(ultimo),
            "source": "ids",
            "event_type": "endpoint_scan",
            "severity": severity,
            "title": "Posible escaneo de endpoints",
            "description": description,
            "details": {
                "rule_id": self.pattern_id,
                "source_ip": ip,
                "targets": len(endpoints),
                "target_ips": endpoints,
                "ports": puertos,
                "connections": len(ventana),
                "threshold": self.threshold,
                "window_seconds": self.window,
                "first_seen": self._utc(primero),
                "last_seen": self._utc(ultimo),
            },
        }

    def _find_scans(self, conexiones):
        # Devuelve (inicio, fin) de cada escaneo: una IP que contacta con al menos
        # `threshold` endpoints distintos dentro de `window` segundos. El escaneo
        # continúa mientras la siguiente conexión llegue antes de `window` segundos,
        # así se genera una sola detección por escaneo y no una por conexión.
        escaneos = []
        i = 0
        while i < len(conexiones):
            endpoints = set()
            alcanzado = None

            for j in range(i, len(conexiones)):
                if self._seconds_between(conexiones[i][0], conexiones[j][0]) > self.window:
                    break
                endpoints.add(conexiones[j][1])
                if len(endpoints) >= self.threshold:
                    alcanzado = j
                    break

            if alcanzado is None:
                i += 1
                continue

            j = alcanzado
            while (j + 1 < len(conexiones)
                   and self._seconds_between(conexiones[j][0], conexiones[j + 1][0]) <= self.window):
                j += 1

            escaneos.append((i, j))
            i = j + 1
        return escaneos

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
        print(f"{self.pattern_id},{self.threshold},{self.window}")