import hmac
import os
import re

from flask import Blueprint, jsonify, request
from util.rule_manager import RuleManager, RuleValidationError


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")
VALID_RULES = ("P004", "P005")
rule_manager = RuleManager()


@admin_bp.before_request
def protect_admin_api():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        return jsonify({"error": "Admin API solo disponible desde localhost"}), 403

    expected_token = os.getenv("IDS_ADMIN_TOKEN")
    if expected_token:
        authorization = request.headers.get("Authorization", "")
        scheme, _, received_token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            received_token, expected_token
        ):
            return jsonify({"error": "Token de administración inválido"}), 401


@admin_bp.get("/rules")
def list_rules():
    return jsonify({"rules": list(VALID_RULES)}), 200


@admin_bp.post("/rules/<rule_id>/disable")
def disable_rule(rule_id):
    if not re.fullmatch(r"P\d{3}", rule_id) or rule_id not in VALID_RULES:
        return jsonify({"error": "Regla inexistente o inválida"}), 404

    data = request.get_json(silent=True) or {}
    requested_rule_id = data.get("rule_id", rule_id)
    if requested_rule_id != rule_id:
        return jsonify({"error": "El identificador de regla no coincide"}), 400

    return jsonify({
        "status": "pending",
        "message": "Desactivación pendiente de implementación",
        "rule_id": requested_rule_id,
    }), 200


@admin_bp.post("/rules/<rule_id>/edit")
def edit_rule(rule_id):
    if not re.fullmatch(r"P\d{3}", rule_id) or rule_id not in VALID_RULES:
        return jsonify({"error": "Regla inexistente o inválida"}), 404

    data = request.get_json(silent=True) or {}
    requested_rule_id = data.get("rule_id", rule_id)
    if requested_rule_id != rule_id:
        return jsonify({"error": "El identificador de regla no coincide"}), 400

    if "threshold" not in data or "window" not in data:
        return jsonify({"error": "Debe indicar threshold y window para editar la regla"}), 400

    extra_args = data.get("extra_args") if "extra_args" in data else None

    try:
        updated_rule = rule_manager.edit_rule(
            rule_id=requested_rule_id,
            threshold=data.get("threshold"),
            window=data.get("window"),
            extra_args=extra_args,
        )
    except RuleValidationError as err:
        return jsonify({"error": str(err)}), 400
    except KeyError:
        return jsonify({"error": "Regla no encontrada en configuración"}), 404

    return jsonify(
        {
            "status": "ok",
            "message": "Regla editada correctamente",
            "rule": updated_rule,
        }
    ), 200
