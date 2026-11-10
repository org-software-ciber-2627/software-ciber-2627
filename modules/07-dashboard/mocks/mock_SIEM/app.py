import json
from pathlib import Path

from flask import Flask, jsonify

app = Flask(__name__)

# SIEM de prueba para la demo del Dashboard (probar.sh -d / probar.ps1 -d).
# El SIEM real del docker-compose no tiene PostgreSQL ni el perfil "persistence", así que responde
# 503 a POST /events y GET /alerts devuelve siempre {"alerts": []}. Este servicio sustituye al
# servicio "siem" solo en la demo y sirve las alertas de ejemplo de mocks/siem-alerts.json con el
# mismo formato que el SIEM real: GET /alerts -> {"alerts": [...]} y GET /alerts/{id} -> una alerta.
FICHERO = Path(__file__).with_name("siem-alerts.json")
ALERTAS = json.loads(FICHERO.read_text(encoding="utf-8"))["alerts"]


@app.route("/alerts", methods=["GET"])
def listar_alertas():
    return jsonify({"alerts": ALERTAS})


@app.route("/alerts/<alert_id>", methods=["GET"])
def detalle_alerta(alert_id):
    for alerta in ALERTAS:
        if alerta["alert_id"] == alert_id:
            return jsonify(alerta)
    return jsonify({"error": "alerta no encontrada"}), 404


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "module": "05-siem (mock de demo)"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
