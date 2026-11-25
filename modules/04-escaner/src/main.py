from flask import Flask, jsonify, request
from runner import get_profiles
from jobs import create_job, get_job, public
from reports import reports_bp
from auth import require_roles
from history import init_db, list_jobs   
import os
import logging

app = Flask(__name__)
app.register_blueprint(reports_bp)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

init_db()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "module": "04-escaner",
    }), 200

@app.route("/events", methods=["GET"])
@app.route("/scans", methods=["GET"])
@require_roles("admin", "analista", "servicio")
def listar_escaneos():
    limit = request.args.get("limit", default=100, type=int)
    return jsonify(list_jobs(limit=max(1, min(limit, 1000)))), 200

@app.route("/scan", methods=["POST"])
@require_roles("admin", "analista") 
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    profile = data.get("profile", "vuln")
    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "falta 'target'"}), 400
    target = target.strip()
    if profile not in get_profiles():
        return jsonify({"error": f"perfil no válido: {get_profiles()}"}), 400

    job = create_job(target, profile)
    return jsonify(public(job)), 200

@app.route("/scan/<scan_id>", methods=["GET"])
@require_roles("admin", "analista", "servicio") 
def scan_status(scan_id):
    job = get_job(scan_id)
    if job is None:
        return jsonify({"error": "scan no encontrado"}), 404
    return jsonify(public(job))

@app.route("/diff", methods=["GET"])
@require_roles("admin", "analista", "servicio")
def diff():
    base_id = request.args.get("base")
    target_id = request.args.get("target")

    if not base_id or not target_id:
        return jsonify({"error": "Se requieren los parámetros 'base' y 'target' con los IDs de los escaneos"}), 400

    job_base = get_job(base_id)
    job_target = get_job(target_id)

    if not job_base or not job_target:
        return jsonify({"error": "Uno o ambos escaneos no fueron encontrados"}), 404

    estados = [job_base.get("status"), job_target.get("status")]

    if "failed" in estados:
        return jsonify({
            "error": "No se pueden comparar escaneos fallidos"
        }), 409

    if any(estado in ("pending", "running") for estado in estados):
        return jsonify({
            "error": "Ambos escaneos deben terminar antes de compararlos"
        }), 409

    if any(estado != "completed" for estado in estados):
        return jsonify({
            "error": "Uno de los escaneos tiene un estado no válido"
        }), 500
    
    events_base = job_base.get("events", [])
    events_target = job_target.get("events", [])

    def get_signature(ev):
        t = ev.get("details", {}).get("target", {})
        return (t.get("ip"), t.get("port"), ev.get("title"))

    base_sigs = {get_signature(ev): ev for ev in events_base}
    target_sigs = {get_signature(ev): ev for ev in events_target}

    base_keys = set(base_sigs.keys())
    target_keys = set(target_sigs.keys())

    new_keys = target_keys - base_keys
    fixed_keys = base_keys - target_keys
    unchanged_keys = base_keys.intersection(target_keys)

    return jsonify({
        "base_scan_id": base_id,
        "target_scan_id": target_id,
        "diff": {
            "new": [target_sigs[k] for k in new_keys],
            "fixed": [base_sigs[k] for k in fixed_keys],
            "unchanged": [base_sigs[k] for k in unchanged_keys]
        }
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "80")),
    )
