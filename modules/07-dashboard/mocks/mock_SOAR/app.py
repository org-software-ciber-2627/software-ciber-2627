from flask import Flask, jsonify

app = Flask(__name__)

INCIDENTS = [
    {
        "id": 1,
        "title": "Intento de acceso no autorizado",
        "severity": "high",
        "status": "open",
        "source": "IDS",
        "description": "Múltiples intentos de acceso fallidos detectados."
    },
    {
        "id": 2,
        "title": "Actividad sospechosa en la red",
        "severity": "medium",
        "status": "investigating",
        "source": "SIEM",
        "description": "Se ha detectado tráfico de red inusual."
    },
    {
        "id": 3,
        "title": "Escaneo de puertos detectado",
        "severity": "low",
        "status": "closed",
        "source": "IDS",
        "description": "Se ha detectado un escaneo de puertos."
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
