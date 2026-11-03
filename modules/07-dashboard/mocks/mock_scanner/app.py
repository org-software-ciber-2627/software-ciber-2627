from flask import Flask, jsonify

app = Flask(__name__)

# Formato deducido del código del Escáner en main (main.py, jobs.py y parser.py). Equipo 4 aún no
# ha publicado su contrato, así que no está confirmado. Las rutas son las suyas: GET /events lista
# los escaneos sin sus eventos y GET /scan/<id> devuelve un escaneo con ellos. El último de la
# lista es el más reciente.
SCANS = [
    {
        "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01",
        "target": "192.168.56.10",
        "profile": "vuln",
        "status": "completed",
        "events": [
            {
                "event_id": "0c2d8a4e-1b3f-4a6c-8d9e-aa11bb22cc01",
                "timestamp": "2026-10-20T10:15:00Z",
                "source": "vulnerability_scanner",
                "event_type": "vulnerability_detected",
                "severity": "high",
                "title": "CVE-2014-0160",
                "description": "VULNERABLE:",
                "target": {"ip": "192.168.56.10", "port": 443, "protocol": "tcp", "service": "https"},
                "details": {
                    "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01",
                    "tool": "nmap",
                    "profile": "vuln",
                    "script_id": "ssl-heartbleed",
                    "evidence": "VULNERABLE:\nThe Heartbleed Bug is a serious vulnerability in OpenSSL.\n  CVE-2014-0160  7.5",
                    "cve": "CVE-2014-0160",
                    "cvss": 7.5
                }
            },
            {
                "event_id": "0c2d8a4e-1b3f-4a6c-8d9e-aa11bb22cc02",
                "timestamp": "2026-10-20T10:15:00Z",
                "source": "vulnerability_scanner",
                "event_type": "vulnerability_detected",
                "severity": "critical",
                "title": "CVE-2017-5638",
                "description": "VULNERABLE:",
                "target": {"ip": "192.168.56.10", "port": 8080, "protocol": "tcp", "service": "http-proxy"},
                "details": {
                    "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01",
                    "tool": "nmap",
                    "profile": "vuln",
                    "script_id": "http-vuln-cve2017-5638",
                    "evidence": "VULNERABLE:\nApache Struts Remote Code Execution Vulnerability\n  CVE-2017-5638  9.8",
                    "cve": "CVE-2017-5638",
                    "cvss": 9.8
                }
            },
            {
                "event_id": "0c2d8a4e-1b3f-4a6c-8d9e-aa11bb22cc03",
                "timestamp": "2026-10-20T10:15:00Z",
                "source": "vulnerability_scanner",
                "event_type": "vulnerability_detected",
                "severity": "medium",
                "title": "http-slowloris-check",
                "description": "LIKELY VULNERABLE:",
                "target": {"ip": "192.168.56.10", "port": 80, "protocol": "tcp", "service": "http"},
                "details": {
                    "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c01",
                    "tool": "nmap",
                    "profile": "vuln",
                    "script_id": "http-slowloris-check",
                    "evidence": "LIKELY VULNERABLE:\nSlowloris DOS attack",
                    "cve": None,
                    "cvss": None
                }
            }
        ]
    },
    {
        "scan_id": "5b0f1c6e-7a3d-4e21-9c58-0d1f2a3b4c02",
        "target": "192.168.56.20",
        "profile": "quick",
        "status": "running",
        "events": []
    }
]

@app.route("/events", methods=["GET"])
def get_scans():
    return jsonify([{k: v for k, v in s.items() if k != "events"} for s in SCANS])

@app.route("/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    for s in SCANS:
        if s["scan_id"] == scan_id:
            return jsonify(s)
    return jsonify({"error": "scan no encontrado"}), 404

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
