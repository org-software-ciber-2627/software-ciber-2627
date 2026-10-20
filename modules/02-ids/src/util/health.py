from flask import Flask, jsonify

app = Flask("health-check")

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "module": "02-ids"
    }), 200