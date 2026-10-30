from flask import Blueprint, current_app, jsonify
from jobs import get_job

reports_bp = Blueprint("reports", __name__)

def respuesta_error(codigo, mensaje, http_status):
    return jsonify({
        "error": {
            "codigo": codigo,
            "mensaje": mensaje,
        }
    }), http_status

@reports_bp.route("/scans/<scan_id>/report", methods=["GET"])
def consultar_informe(scan_id):
    """Consulta los eventos del escaneo guardados en memoria por jobs.py."""
    try:
        job = get_job(scan_id)

        if job is None:
            return respuesta_error(
                    "SCAN_NOT_FOUND",
                    "No existe un escaneo con ese identificador",
                    404
            )

        status = job.get("status")
        if status in ("pending", "running"):
            return jsonify({
                "scan_id": scan_id,
                "estado": (
                  "pendiente" if status == "pending" else "en_curso"
                ),
                "mensaje": "El informe todavía no está disponible",
            }), 202

        if status == "failed":
            current_app.logger.error(
                "Escaneo %s fallido: %s",
                scan_id,
                job.get("error", "Sin detalles"),
            )
            return respuesta_error(
                "SCAN_FAILED",
                "El escaneo ha fallado y no hay un informe disponible",
                500,
            )

        events = job.get("events")

        if status != "completed" or not isinstance(events, list):
            current_app.logger.error(
                "Informe inválido para el escaneo %s: estado=%r",
                scan_id,
                status,
            )
            return respuesta_error(
                "INTERNAL_ERROR",
                "No se pudo recuperar el informe",
                500,
            )

        return jsonify(events), 200

    except Exception:
        current_app.logger.exception(
            "Error inesperado al consultar el escaneo %s",
            scan_id,
        )
        return respuesta_error(
            "INTERNAL_ERROR",
            "No se pudo recuperar el informe",
            500,
        )