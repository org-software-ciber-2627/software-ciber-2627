import ipaddress
from datetime import datetime

from util.pattern_loader import pattern
from util.pattern_base import PatternBase


@pattern("P005", "Escaneo de Endpoints", "Medio")
class EndpointScan(PatternBase):

    def __init__(self, threshold, window, *args, **kwargs):
        super().__init__()

        # Parámetros definidos en ids.rules
        # threshold = nº mínimo de endpoints distintos
        # window = ventana temporal en segundos
        self.threshold = int(threshold)
        self.window = int(window)

        self.args = args
        self.kwargs = kwargs

        # Convertimos las entradas de la whitelist a objetos ip_network
        # para poder comprobar si una IP pertenece a una red permitida.
        self.whitelist_networks = [
            ipaddress.ip_network(entry, strict=False)
            for entry in self.whitelist
        ]

    def run(self, eventos):

        # Diccionario:
        # {
        #   "192.168.1.50": [
        #       (timestamp, "192.168.1.10"),
        #       (timestamp, "192.168.1.11"),
        #       ...
        #   ]
        # }
        conexiones_por_ip = {}

        # Agrupar todas las conexiones por IP origen
        for evento in eventos:

            source_ip = evento.get("source_ip")
            destination_ip = evento.get("destination_ip")

            if source_ip is None or destination_ip is None:
                continue

            # Ignoramos direcciones incluidas en whitelist
            if self._in_whitelist(source_ip):
                continue

            timestamp = self._parse_time(evento["timestamp"])

            conexiones_por_ip.setdefault(
                source_ip,
                []
            ).append(
                (timestamp, destination_ip)
            )

        detecciones = []

        # Analizamos cada IP origen individualmente
        for ip, conexiones in conexiones_por_ip.items():

            # Orden cronológico
            conexiones.sort(key=lambda conexion: conexion[0])

            # Buscar posibles escaneos
            for inicio, fin in self._find_scans(conexiones):

                ventana = conexiones[inicio:fin + 1]

                # Endpoints únicos visitados
                endpoints = {
                    destino
                    for _, destino in ventana
                }

                detecciones.append({
                    "source_ip": ip,
                    "targets": len(endpoints),
                    "target_ips": sorted(endpoints),
                    "first_seen": ventana[0][0].isoformat(),
                    "last_seen": ventana[-1][0].isoformat(),
                    "window_seconds": self.window
                })

        print(f"--- Ejecutando {self.name} (ID: {self.pattern_id}) ---")
        print(f"    Detecciones: {len(detecciones)}")

        return detecciones

    def _find_scans(self, conexiones):
        """
        Busca ventanas temporales donde una misma IP contacte
        con al menos 'threshold' endpoints distintos durante
        'window' segundos.

        Devuelve pares (inicio, fin).
        """

        detecciones = []

        for i in range(len(conexiones)):

            endpoints = set()

            for j in range(i, len(conexiones)):

                tiempo = self._seconds_between(
                    conexiones[i][0],
                    conexiones[j][0]
                )

                # Hemos salido de la ventana temporal
                if tiempo > self.window:
                    break

                endpoints.add(conexiones[j][1])

                # Umbral alcanzado
                if len(endpoints) >= self.threshold:

                    detecciones.append((i, j))

                    # Saltamos a la siguiente búsqueda
                    break

        return detecciones

    def _in_whitelist(self, ip):
        """
        Comprueba si la IP pertenece
        a alguna red permitida.
        """

        try:
            direccion = ipaddress.ip_address(ip)
        except ValueError:
            return False

        return any(
            direccion in red
            for red in self.whitelist_networks
        )

    @staticmethod
    def _parse_time(timestamp):
        """
        Convierte:
            Oct 27 15:10:00

        a objeto datetime.
        """

        return datetime.strptime(
            f"{datetime.now().year} {timestamp}",
            "%Y %b %d %H:%M:%S"
        )

    @staticmethod
    def _seconds_between(inicio, fin):
        """
        Diferencia entre dos timestamps
        expresada en segundos.
        """

        return (fin - inicio).total_seconds()

    def print(self):
        print(
            f"{self.pattern_id},"
            f"{self.threshold},"
            f"{self.window}"
        )