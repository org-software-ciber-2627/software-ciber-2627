from flask import Flask, jsonify, request

from jobs import JOBS, create_job, get_job, public
from runner import get_profiles

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/scan")
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    profile = data.get("profile", "vuln")

    if not target:
        return jsonify({"error": "falta 'target'"}), 400
    if profile not in get_profiles():
        return jsonify({"error": f"perfil no válido: {get_profiles()}"}), 400

    return jsonify(public(create_job(target, profile))), 200


@app.get("/scan/<scan_id>")
def scan_status(scan_id):
    job = get_job(scan_id)
    if job is None:
        return jsonify({"error": "scan no encontrado"}), 404
    return jsonify(public(job)), 200


@app.get("/events")
def history():
    result = []
    for scan_id in JOBS:
        entry = public(get_job(scan_id))
        entry.pop("events", None)
        result.append(entry)
    return jsonify(result), 200


@app.get("/diff")
def diff():
    base_id = request.args.get("base")
    target_id = request.args.get("target")

    if not base_id or not target_id:
        return jsonify({"error": "Se requieren los parámetros 'base' y 'target' con los IDs de los escaneos"}), 400

    job_base = get_job(base_id)
    job_target = get_job(target_id)
    if not job_base or not job_target:
        return jsonify({"error": "Uno o ambos escaneos no fueron encontrados"}), 404

    events_base = job_base.get("events", [])
    events_target = job_target.get("events", [])

    def signature(event):
        target = event.get("target", {})
        return (target.get("ip"), target.get("port"), event.get("title"))

    base_sigs = {signature(event): event for event in events_base}
    target_sigs = {signature(event): event for event in events_target}

    base_keys = set(base_sigs.keys())
    target_keys = set(target_sigs.keys())

    return jsonify(
        {
            "base_scan_id": base_id,
            "target_scan_id": target_id,
            "diff": {
                "new": [target_sigs[key] for key in target_keys - base_keys],
                "fixed": [base_sigs[key] for key in base_keys - target_keys],
                "unchanged": [base_sigs[key] for key in base_keys.intersection(target_keys)],
            },
        }
    ), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
