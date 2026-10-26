from util.pattern_loader import pattern
from util.pattern_base import PatternBase


@pattern("P002", "Patrón 2", "Medio")
class Pattern2(PatternBase):
    def __init__(self, threshold, window, *args, **kwargs):
        super().__init__()

        self.threshold = threshold
        self.window = window
        self.args = args
        self.kwargs = kwargs

    def run(self, eventos):
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
