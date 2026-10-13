# ---------------------------------------------------------
# HU1: 
# ---------------------------------------------------------

import time
import logging
import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------
# Configuración
# ---------------------------------------------------------
BASE_URL = "https://mock-siem.example.com"   # URL mock, CAMBIAR EN PRODUCCIÓN
ENDPOINT = "/alerts"
POLL_INTERVAL = 30                           # intervalo de sondeo (segundos)
TIMEOUT = 5                                   # timeout HTTP
MAX_RETRIES = 3                               # número máximo de reintentos
BACKOFF_FACTOR = 2                            # backoff exponencial

# TOKEN DE EJEMPLO, CAMBIAR EN PRODUCCIÓN
AUTH_TOKEN = "mock-token-123"

# ---------------------------------------------------------
# Logger
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# ---------------------------------------------------------
# Cliente HTTP
# ---------------------------------------------------------
def get_alertas():
    url = BASE_URL + ENDPOINT
    headers = {
        "Authorization": f"Bearer {AUTH_TOKEN}",
        "Accept": "application/json"
    }

    for intento in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)

            # Si el SIEM devuelve un error HTTP
            if response.status_code >= 400:
                logging.error(f"Error HTTP {response.status_code}: {response.text}")
                return None

            return response.json()

        except RequestException as e:
            logging.warning(f"Error de red (intento {intento}/{MAX_RETRIES}): {e}")

            # Backoff exponencial simple
            tiempo_espera = BACKOFF_FACTOR ** (intento - 1)
            logging.info(f"Reintentando en {tiempo_espera}s...")
            time.sleep(tiempo_espera)

    logging.error("Fallo definitivo tras varios intentos.")
    return None

# ---------------------------------------------------------
# Servicio de sondeo (polling)
# ---------------------------------------------------------
def servicio_polling():
    logging.info("Servicio de sondeo iniciado.")

    while True:
        logging.info("Llamando a GET /alerts...")
        alertas = get_alertas()

        if alertas is not None:
            logging.info(f"Alertas recibidas: {alertas}")
        else:
            logging.info("No se recibieron alertas o hubo un error.")

        time.sleep(POLL_INTERVAL)

# ---------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------
if __name__ == "__main__":
    servicio_polling()
