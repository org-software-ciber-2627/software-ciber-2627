from util.pattern_loader import pattern


@pattern("P001", "Patrón 1", "Alto")
class Pattern1:
    def __init__(self, threshold, window, *args, **kwargs):
        self.threshold = threshold
        self.window = window
        self.args = args
        self.kwargs = kwargs

    def run(self):
        print(f"--- Ejecutando {self.name} (ID: {self.pattern_id}) ---")
        print(f"    Riesgo: {self.risk}")
        print(
            f"    Condición: {self.threshold} intentos "
            f"en {self.window} segundos."
        )
        print(f"    Log configurado: {self.log_file}")
        print(f"    IPs ignoradas: {self.whitelist}")

    def print(self):
        print(f"{self.pattern_id},{self.threshold},{self.window}")
