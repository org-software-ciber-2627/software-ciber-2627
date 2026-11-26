from flask import Flask, jsonify, request
from runner import get_profiles
from jobs import create_job, get_job, public
from reports import reports_bp
from auth import require_roles
from history import init_db, list_jobs   
import os
import logging
from collections import Counter

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
    escaneos = list_jobs(limit=max(1, min(limit, 1000)))
    return jsonify([{k: v for k, v in e.items() if k != "events"} for e in escaneos]), 200

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
    
    events_base = job_base.get("events")
    events_target = job_target.get("events")

    def get_signature(event):
        if not isinstance(event, dict):
            raise ValueError("El evento no es un objeto")
        details = event.get("details")
        target = details.get("target") if isinstance(details, dict) else None
        if not isinstance(target, dict):
            raise ValueError("El evento no contiene details.target válido")
        return (target.get("ip"), target.get("port"), event.get("title"))

    try:
        if not isinstance(events_base, list) or not isinstance(events_target, list):
            raise ValueError("La lista de eventos no es válida")
        base_signatures = [get_signature(event) for event in events_base]
        target_signatures = [get_signature(event) for event in events_target]
    except (TypeError, ValueError):
        return jsonify({"error": "Los eventos de uno de los escaneos no son válidos"}), 500

    # La firma acordada no es necesariamente única. Contar ocurrencias evita
    # perder eventos cuando un escaneo registra varios hallazgos equivalentes.
    base_counts = Counter(base_signatures)
    target_counts = Counter(target_signatures)
    unchanged_counts = base_counts & target_counts

    unchanged_seen = Counter()
    fixed = []
    unchanged = []
    for event, signature in zip(events_base, base_signatures):
        if unchanged_seen[signature] < unchanged_counts[signature]:
            unchanged.append(event)
            unchanged_seen[signature] += 1
        else:
            fixed.append(event)

    target_seen = Counter()
    new = []
    for event, signature in zip(events_target, target_signatures):
        if target_seen[signature] >= unchanged_counts[signature]:
            new.append(event)
        target_seen[signature] += 1

    return jsonify({
        "base_scan_id": base_id,
        "target_scan_id": target_id,
        "diff": {
            "new": new,
            "fixed": fixed,
            "unchanged": unchanged
        }
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "80")),
    )
