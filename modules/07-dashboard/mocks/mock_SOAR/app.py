from flask import Flask, jsonify

app = Flask(__name__)

# Formato del borrador de Equipo 6 (rama equipo-06-soar/SB-13-listar-incidentes, contract/incidents.md).
# Aún no está en main: no está confirmado. Las alertas de origen son las del mock del SIEM.
INCIDENTS = [
    {
        "incident_id": "INC-001",
        "alert_id": "SIEM-ALERT-EJEMPLO-002",
        "event_type": "fuerza_bruta",
        "severity": "medium",
        "source_ip": "192.168.1.50",
        "status": "open",
        "created_at": "2026-09-22T18:30:20Z",
        "resolved_at": None
    },
    {
        "incident_id": "INC-002",
        "alert_id": "SIEM-ALERT-EJEMPLO-001",
        "event_type": "port_scan",
        "severity": "medium",
        "source_ip": "192.168.1.50",
        "status": "in_progress",
        "created_at": "2026-09-22T18:31:10Z",
        "resolved_at": None
    },
    {
        "incident_id": "INC-003",
        "alert_id": "SIEM-ALERT-EJEMPLO-003",
        "event_type": "vulnerability_detected",
        "severity": "medium",
        "source_ip": None,
        "status": "resolved",
        "created_at": "2026-09-29T10:35:00Z",
        "resolved_at": "2026-09-29T11:20:00Z"
    }
]

@app.route("/incidents", methods=["GET"])
def get_incidents():
    return jsonify(INCIDENTS)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
