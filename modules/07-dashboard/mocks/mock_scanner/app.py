from flask import Flask, jsonify

app = Flask(__name__)

FINDINGS = [
    {
        "id": 1,
        "target": "192.168.1.10",
        "title": "Puerto SSH expuesto",
        "severity": "high",
        "status": "open",
        "description": "El puerto 22 está accesible."
    },
    {
        "id": 2,
        "target": "192.168.1.20",
        "title": "Servicio HTTP detectado",
        "severity": "medium",
        "status": "open",
        "description": "Se ha detectado un servicio HTTP en el puerto 80."
    },
    {
        "id": 3,
        "target": "192.168.1.30",
        "title": "Servicio con información de versión",
        "severity": "low",
        "status": "resolved",
        "description": "El servicio expone información sobre su versión."
    }
]

@app.route("/findings", methods=["GET"])
def get_findings():
    return jsonify(FINDINGS)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
