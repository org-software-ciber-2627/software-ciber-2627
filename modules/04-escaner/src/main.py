from flask import Flask, jsonify, request
from runner import get_profiles
from jobs import create_job, get_job, public, JOBS
from reports import reports_bp

app = Flask(__name__)
app.register_blueprint(reports_bp)

@app.route("/scan", methods=["POST"]) # metodo para realizar el escaneo
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    profile = data.get("profile", "vuln")
    if not target:
        return jsonify({"error": "falta 'target'"}), 400
    if profile not in get_profiles():
        return jsonify({"error": f"perfil no válido: {get_profiles()}"}), 400

    job = create_job(target, profile)
    return jsonify(public(job)), 200

@app.route("/scan/<scan_id>", methods=["GET"]) # metodo para obtener los resultados del escaneo
def scan_status(scan_id):
    job = get_job(scan_id)
    if job is None:
        return jsonify({"error": "scan no encontrado"}), 404
    return jsonify(public(job))


@app.route("/events", methods=["GET"]) # metodo para ver el histórico  de escaneos
def history():
    result = []
    for scan_id in JOBS:
        j = public(get_job(scan_id))   # refresca el estado de cada uno
        j.pop("events")
        result.append(j)
    return jsonify(result)


@app.route("/diff", methods=["GET"])
def diff():
    # Obtenemos los IDs de los escaneos a comparar por parámetros GET: /diff?base=ID1&target=ID2
    base_id = request.args.get("base")
    target_id = request.args.get("target")

    if not base_id or not target_id:
        return jsonify({"error": "Se requieren los parámetros 'base' y 'target' con los IDs de los escaneos"}), 400

    job_base = get_job(base_id)
    job_target = get_job(target_id)

    if not job_base or not job_target:
        return jsonify({"error": "Uno o ambos escaneos no fueron encontrados"}), 404

    # Extraemos los eventos de cada escaneo (asegurándonos de refrescar el job)
    events_base = job_base.get("events", [])
    events_target = job_target.get("events", [])

    # Función auxiliar para crear una firma única de cada vulnerabilidad
    def get_signature(ev):
        t = ev.get("target", {})
        # Identificamos el hallazgo por IP, Puerto y el Título (CVE o script_id)
        return (t.get("ip"), t.get("port"), ev.get("title"))

    # Mapeamos los identificadores únicos a sus respectivos eventos
    base_sigs = {get_signature(ev): ev for ev in events_base}
    target_sigs = {get_signature(ev): ev for ev in events_target}

    base_keys = set(base_sigs.keys())
    target_keys = set(target_sigs.keys())

    # Calculamos diferencias
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
    app.run(host="0.0.0.0", port=8004)