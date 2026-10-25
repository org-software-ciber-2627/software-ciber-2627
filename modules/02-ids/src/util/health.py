from flask import Flask, jsonify, request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from werkzeug.exceptions import RequestEntityTooLarge
from util.config_loader import config
import json

app = Flask("health-check")

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "module": "02-ids"
    }), 200

app.config["MAX_CONTENT_LENGTH"]=5*1024*1024 #We allow the 1000 logs established in the contract, but also check the lines aren't excessively long
                                            #If the lines are too long then Flask should return error 413 (Request Entity Too Large)
log_path = Path(config["LOGFILE"]).resolve()
RECEIVED_LOG_FILE=log_path.with_name("received.log")
RECEIVED_IDS_FILE=log_path.with_name("received_ids.json")

file_lock=Lock() #Prevents writing in the file from various threads at the same time

def load_records():
    if not RECEIVED_IDS_FILE.exists():
        return{}
    with RECEIVED_IDS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)

def save_records(records):
    RECEIVED_IDS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with RECEIVED_IDS_FILE.open("w", encoding="utf-8") as file:
        json.dump(records, file, ensure_ascii=False, indent=2)


def write_log_file(records):
    RECEIVED_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with RECEIVED_LOG_FILE.open("w", encoding="utf-8") as file:
        for record in records.values():
            file.write(record["raw_line"] + "\n")


def cleanup_old_logs():
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)

    with file_lock:
        records = load_records()
        valid_records = {}

        for log_id, record in records.items():
            received_at = datetime.fromisoformat(record["received_at"])

            if received_at >= cutoff:
                valid_records[log_id] = record

        save_records(valid_records)
        write_log_file(valid_records)

@app.route("/logs", methods=["POST"])
def receive_logs():
    if request.mimetype != "application/json":
        return jsonify({
            "error": "Content-Type must be application/json"
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON body"}), 400

    source = data.get("source")
    logs = data.get("logs")

    if not isinstance(source, str) or not source.strip():
        return jsonify({"error": "Invalid source"}), 400

    if not isinstance(logs, list) or len(logs) == 0:
        return jsonify({
            "error": "logs must contain at least one entry"
        }), 400

    if len(logs) > 1000:
        return jsonify({
            "error": "Maximum batch size is 1000"
        }), 413

    for entry in logs:
        if not isinstance(entry, dict):
            return jsonify({
                "error": "Each log must be an object"
            }), 400

        log_id = entry.get("id")
        raw_line = entry.get("raw_line")

        if not isinstance(log_id, str) or not log_id.strip():
            return jsonify({
                "error": "Each log needs a valid id"
            }), 400

        if not isinstance(raw_line, str) or not raw_line.strip():
            return jsonify({
                "error": "Each log needs a non-empty raw_line"
            }), 400

        if "\n" in raw_line or "\r" in raw_line:
            return jsonify({
                "error": "raw_line must contain a single line"
            }), 400

    accepted = 0
    duplicates = 0

    with file_lock:
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        records = load_records()

        records = {
            log_id: record
            for log_id, record in records.items()
            if datetime.fromisoformat(record["received_at"]) >= cutoff
        }

        for entry in logs:
            log_id = entry["id"]

            if log_id in records:
                duplicates += 1
                continue

            records[log_id] = {
                "source": source,
                "raw_line": entry["raw_line"],
                "received_at": datetime.now(timezone.utc).isoformat()
            }

            accepted += 1

        save_records(records)
        write_log_file(records)

    return jsonify({
        "status": "accepted",
        "accepted": accepted,
        "duplicates": duplicates
    }), 202


@app.errorhandler(RequestEntityTooLarge)
def request_too_large(error):
    return jsonify({
        "error": "Request body too large"
    }), 413

cleanup_old_logs()