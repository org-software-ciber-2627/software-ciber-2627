from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/events", methods=["POST"])
def receive_event():
    data = request.get_json(silent=True) or {}
    print("\n--- [MOCK SIEM] Evento de vulnerabilidad recibido ---")
    print(f"ID del Evento : {data.get('event_id')}")
    print(f"Tipo          : {data.get('event_type')}")
    print(f"Severidad     : {data.get('severity')}")
    print(f"Título        : {data.get('title')}")
    print(f"Objetivo      : {data.get('target', {}).get('ip')}:{data.get('target', {}).get('port')}")
    print("----------------------------------------------------\n")
    return jsonify({"status": "received", "event_id": data.get("event_id")}), 200

if __name__ == "__main__":
    # Corre en el puerto 8005 que es el que tenemos configurado por defecto en jobs.py
    app.run(host="0.0.0.0", port=8005)
