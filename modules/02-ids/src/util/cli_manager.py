import logging
import os

import requests


logger = logging.getLogger(__name__)


def _show_menu():
    print("\n=== Gestión del IDS ===")
    print("1. Desactivar una regla del IDS")
    print("2. Editar una regla del IDS existente")
    print("3. Borrar una regla del IDS existente")
    print("4. Mostrar/listar las alertas generadas por el motor")
    print("5. Salir")


def _disable_rule():
    rule_id = input("Introduzca el identificador de la regla: ").strip()
    if not rule_id:
        print("El identificador de la regla no puede estar vacío.")
        return

    api_url = os.getenv("IDS_ADMIN_API_URL", "http://127.0.0.1:80")
    headers = {}
    admin_token = os.getenv("IDS_ADMIN_TOKEN")
    if admin_token:
        headers["Authorization"] = f"Bearer {admin_token}"

    try:
        response = requests.post(
            f"{api_url}/admin/rules/{rule_id}/disable",
            json={"rule_id": rule_id},
            headers=headers,
            timeout=5,
        )
        response.raise_for_status()
        print(response.json().get("message", "Respuesta recibida del servidor IDS."))
    except requests.RequestException as error:
        logger.warning("No se pudo contactar con la API administrativa del IDS: %s", error)
        print("No se pudo contactar con el servidor IDS.")


def _edit_rule():
    rule_id = input("Introduzca el identificador de la regla: ").strip()
    if not rule_id:
        print("El identificador de la regla no puede estar vacío.")
        return

    threshold = input("Introduzca el nuevo umbral (threshold): ").strip()
    if not threshold:
        print("El umbral no puede estar vacío.")
        return

    window = input("Introduzca la nueva ventana de segundos (window): ").strip()
    if not window:
        print("La ventana de segundos no puede estar vacía.")
        return

    extra_args = input(
        "Argumentos extra (formato clave=valor;clave2=valor2). Deje vacío para mantener los actuales: "
    ).strip()

    payload = {
        "rule_id": rule_id,
        "threshold": threshold,
        "window": window,
    }
    if extra_args:
        payload["extra_args"] = extra_args

    api_url = os.getenv("IDS_ADMIN_API_URL", "http://127.0.0.1:80")
    headers = {}
    admin_token = os.getenv("IDS_ADMIN_TOKEN")
    if admin_token:
        headers["Authorization"] = f"Bearer {admin_token}"

    try:
        response = requests.post(
            f"{api_url}/admin/rules/{rule_id}/edit",
            json=payload,
            headers=headers,
            timeout=5,
        )
        response.raise_for_status()
        print(response.json().get("message", "Regla actualizada."))
    except requests.HTTPError:
        try:
            error_message = response.json().get("error", "No se pudo editar la regla.")
        except ValueError:
            error_message = "No se pudo editar la regla."
        print(error_message)
    except requests.RequestException as error:
        logger.warning("No se pudo contactar con la API administrativa del IDS: %s", error)
        print("No se pudo contactar con el servidor IDS.")


def run_cli():
    logger.info("Iniciando CLI del IDS.")
    try:
        while True:
            _show_menu()
            try:
                option = input("Seleccione una opción: ")
                option = int(option)
            except ValueError:
                logger.warning("Opción no reconocida: entrada no numérica.")
                print("Opción no reconocida, por favor introduzca un número del 1 al 5.")
                continue

            if option not in range(1, 6):
                logger.warning("Opción no reconocida: fuera de rango (%s).", option)
                print("Opción no reconocida, por favor introduzca un número del 1 al 5.")
                continue

            logger.info("Opción del menú seleccionada: %s", option)

            if option == 1:
                _disable_rule()
            elif option == 2:
                _edit_rule()
            elif option == 3:
                # TODO: implementar borrar de regla. Pendiente para otro desarrollador.
                print("Funcionalidad pendiente de implementación. Volviendo al menú principal...")
            elif option == 4:
                # TODO: implementar listar de alerta. Pendiente para otro desarrollador.
                print("Funcionalidad pendiente de implementación. Volviendo al menú principal...")
            elif option == 5:
                logger.info("Cerrando CLI del IDS.")
                break
    except KeyboardInterrupt:
        logger.info("Interrupción recibida. Cerrando CLI del IDS.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_cli()
