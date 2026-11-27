import json
import logging
import os
import signal
import time
from pathlib import Path
from threading import Event, Thread

import util.health
from util.config_loader import config
from util.health import (
    RECEIVED_LOG_FILE,
    file_lock,
    mark_records_processed,
)
from util.log_parser import parse_log_lines
from util.log_storage import ParsedLogStorage
from util.parsers import parse_rules
from util.siem_publisher import publish_and_queue, retry_pending


logger = logging.getLogger(__name__)
failed_batch_count = 0


def _get_poll_interval():
    try:
        interval = float(os.getenv("IDS_POLL_INTERVAL", "5"))
    except ValueError:
        logger.warning("IDS_POLL_INTERVAL no es válido; se usará 5 segundos.")
        return 5

    if interval < 0:
        logger.warning("IDS_POLL_INTERVAL no puede ser negativo; se usará 5 segundos.")
        return 5

    return interval


def _append_events(events_path: Path, detecciones):
    try:
        with events_path.open(encoding="utf-8") as file:
            existing_events = json.load(file)
    except FileNotFoundError:
        existing_events = []
    except json.JSONDecodeError as error:
        logger.warning("events.json no contiene JSON válido; se reiniciará: %s", error)
        existing_events = []
    except OSError as error:
        logger.warning("No se pudo leer %s; se reiniciará: %s", events_path, error)
        existing_events = []

    if not isinstance(existing_events, list):
        logger.warning("events.json no contiene una lista; se reiniciará.")
        existing_events = []

    with events_path.open("w", encoding="utf-8") as file:
        json.dump(existing_events + detecciones, file, indent=2)


def _save_failed_batch(log_path: Path, contents, error):
    failed_path = log_path.with_name("failed_batches.log")
    with failed_path.open("a", encoding="utf-8") as file:
        file.write(f"Error: {error}\n")
        file.write(contents)
        if not contents.endswith("\n"):
            file.write("\n")
        file.write("---\n")


def _process_log_batch(log_path: Path, rules, storage):
    global failed_batch_count

    try:
        with file_lock:
            try:
                contents = log_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return False
            except OSError as error:
                logger.warning("No se pudo leer %s: %s", log_path, error)
                return False

            if not contents.strip():
                return False

            with log_path.open("w", encoding="utf-8"):
                pass
    except OSError as error:
        logger.warning("No se pudo truncar %s: %s", log_path, error)
        return False

    raw_lines = contents.splitlines()

    logger.info("Nuevos logs detectados. Iniciando ejecución de la app IDS...")
    try:
        eventos = parse_log_lines(raw_lines)
        storage.save_many(eventos)

        detecciones = []
        for rule in rules:
            if rule.enabled:
                detecciones.extend(rule.run(eventos))
            else:
                logger.info("---Regla %s desactivada---", rule.pattern_id)

        if detecciones:
            logger.info("---Se han detectado %s alertas:---", len(detecciones))

            for deteccion in detecciones:
                logger.info("ALERTA: %s", deteccion)
                publish_and_queue(deteccion)
        else:
            logger.info("No se han detectado alertas.")

        retry_pending()

        events_path = Path(__file__).resolve().parents[1] / "output"
        events_path.mkdir(parents=True, exist_ok=True)
        _append_events(events_path / "events.json", detecciones)
        mark_records_processed(raw_lines)
    except Exception as error:
        failed_batch_count += 1
        logger.exception(
            "Error durante el análisis del IDS. Lote fallido #%s: %s",
            failed_batch_count,
            error,
        )
        try:
            _save_failed_batch(log_path, contents, error)
            mark_records_processed(raw_lines, failed=True)
        except OSError as backup_error:
            logger.error("No se pudo guardar el lote fallido: %s", backup_error)
        return True

    logger.info("App IDS finalizada. Lote procesado correctamente.")

    return True


def _poll_logs(stop_event: Event, rules, storage, log_path: Path, interval: float):
    waiting_logged = False
    status_interval = 20 * 60
    last_status = time.monotonic()
    while True:
        if stop_event.is_set():
            break

        has_logs = _process_log_batch(log_path, rules, storage)

        if not has_logs:
            if not waiting_logged:
                logger.info("Esperando nuevos logs en %s...", log_path)
                waiting_logged = True
        else:
            waiting_logged = False

        now = time.monotonic()

        if now - last_status >= status_interval:
            if waiting_logged:
                logger.info(
                    "IDS activo y esperando nuevos logs. "
                    "No se han recibido registros nuevos en los últimos 20 minutos."
                )

            last_status = now

        stop_event.wait(interval)

    logger.info("Cerrando bucle de polling del IDS.")


def main():
    logging.basicConfig(level=logging.INFO)
    stop_event = Event()

    def request_shutdown(signum, _frame):
        logger.info("Señal %s recibida. Cerrando IDS...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)

    app = Thread(
        target=util.health.app.run,
        kwargs={"port": 80, "host": "0.0.0.0"},
        daemon=True,
    )
    app.start()

    rules = parse_rules("config/ids.rules")

    for rule in rules:
        if rule.pattern_id == "P002":
            rule.disable()

    storage = ParsedLogStorage()
    interval = _get_poll_interval()

    logger.info("Log a procesar: %s", RECEIVED_LOG_FILE)
    logger.info("Whitelist: %s", config["WHITELIST"])
    polling = Thread(
        target=_poll_logs,
        args=(stop_event, rules, storage, RECEIVED_LOG_FILE, interval),
        daemon=True,
    )
    polling.start()

    try:
        polling.join()
    except KeyboardInterrupt:
        logger.info("Interrupción recibida. Cerrando servicio IDS.")
        stop_event.set()
        polling.join()


if __name__ == "__main__":
    main()
