# ---------------------------------------------------------
# HU1:
# ---------------------------------------------------------

import logging
import os
import time

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------
# Configuración
# ---------------------------------------------------------
BASE_URL = (os.getenv("SIEM_URL") or os.getenv("SIEM_API_URL") or "http://localhost:8000").rstrip("/")
if BASE_URL.endswith("/alerts"):
    BASE_URL = BASE_URL[: -len("/alerts")]
ENDPOINT = "/alerts"
POLL_INTERVAL = float(os.getenv("SOAR_POLLING_INTERVAL", os.getenv("POLL_INTERVAL_SECONDS", "30")))
TIMEOUT = 5
MAX_RETRIES = 3
BACKOFF_FACTOR = 2
AUTH_TOKEN = os.getenv("SIEM_TOKEN")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def get_alertas():
    url = BASE_URL + ENDPOINT
    headers = {"Accept": "application/json"}
    if AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {AUTH_TOKEN}"

    for intento in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, headers=headers, timeout=TIMEOUT)
            if response.status_code >= 400:
                logging.error("Error HTTP %s: %s", response.status_code, response.text)
                return None
            return response.json()
        except RequestException as exc:
            logging.warning("Error de red (intento %s/%s): %s", intento, MAX_RETRIES, exc)
            tiempo_espera = BACKOFF_FACTOR ** (intento - 1)
            logging.info("Reintentando en %ss...", tiempo_espera)
            time.sleep(tiempo_espera)

    logging.error("Fallo definitivo tras varios intentos.")
    return None


def servicio_polling():
    logging.info("Servicio de sondeo iniciado.")

    while True:
        logging.info("Llamando a GET /alerts...")
        alertas = get_alertas()

        if alertas is not None:
            logging.info("Alertas recibidas: %s", alertas)
        else:
            logging.info("No se recibieron alertas o hubo un error.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    servicio_polling()
