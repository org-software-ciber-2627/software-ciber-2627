from flask import Flask, jsonify

app = Flask(__name__)

# Mock del Escáner (equipo 4) con el contrato acordado: GET /scans y GET /scans/<id>/report.
# Solo para tests; el Dashboard real lee el Escáner real a través de /api/escaner/.
SCAN_OK = "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01"
SCAN_EN_CURSO = "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c02"


def hallazgo(n, severity, title, port, service, script_id, cve, cvss):
    return {
        "event_id": f"0c2d8a4e-1b3f-4a6c-8d9e-aa11bb22cc0{n}",
        "timestamp": "2026-10-20T10:15:00Z",
        "source": "scanner",
        "event_type": "vulnerability_detected",
        "severity": severity,
        "title": title,
        "description": "VULNERABLE:",
        "details": {
            "target": {"ip": "192.168.56.10", "port": port, "protocol": "tcp", "service": service},
            "scan_id": SCAN_OK,
            "tool": "nmap",
            "profile": "vuln",
            "script_id": script_id,
            "evidence": "VULNERABLE:",
            "cve": cve,
            "cvss": cvss,
        },
    }


SCANS = [
    {
        "scan_id": SCAN_EN_CURSO,
        "target": "192.168.56.20",
        "profile": "quick",
        "status": "running",
        "created_at": "2026-10-20T10:20:00Z",
        "events": [],
    },
    {
        "scan_id": SCAN_OK,
        "target": "192.168.56.10",
        "profile": "vuln",
        "status": "completed",
        "created_at": "2026-10-20T10:10:00Z",
        "events": [
            hallazgo(1, "high", "CVE-2014-0160", 443, "https", "ssl-heartbleed", "CVE-2014-0160", 7.5),
            hallazgo(2, "critical", "CVE-2017-5638", 8080, "http-proxy", "http-vuln-cve2017-5638", "CVE-2017-5638", 9.8),
            hallazgo(3, "medium", "http-slowloris-check", 80, "http", "http-slowloris-check", None, None),
        ],
    },
]  # ordenados del más reciente al más antiguo, como el Escáner real


def error(codigo, mensaje, status):
    return jsonify({"error": {"codigo": codigo, "mensaje": mensaje}}), status


@app.route("/events", methods=["GET"])
@app.route("/scans", methods=["GET"])
def list_scans():
    return jsonify([{k: v for k, v in s.items() if k != "events"} for s in SCANS])


@app.route("/scans/<scan_id>/report", methods=["GET"])
def report(scan_id):
    if scan_id == "scan-fallo":  # fuerza un 500 para probar el error
        return error("INTERNAL_ERROR", "No se pudo recuperar el informe", 500)
    for s in SCANS:
        if s["scan_id"] == scan_id:
            if s["status"] != "completed":
                estado = "en_curso" if s["status"] == "running" else "pendiente"
                return jsonify({"scan_id": scan_id, "estado": estado,
                                "mensaje": "El informe todavía no está disponible"}), 202
            return jsonify(s["events"])
    return error("SCAN_NOT_FOUND", "No existe un escaneo con ese identificador", 404)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)