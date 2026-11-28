import json
import logging
import os
import sqlite3
import threading
from contextlib import closing

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("SCAN_DB_PATH", "data/scans.db")
_write_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    target         TEXT NOT NULL,
    profile        TEXT NOT NULL,
    status         TEXT NOT NULL,
    error          TEXT,
    events         TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE TABLE IF NOT EXISTS event_deliveries (
    event_id        TEXT PRIMARY KEY,
    scan_id         TEXT,
    status          TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    event_json      TEXT NOT NULL,
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_deliveries_status ON event_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_deliveries_scan ON event_deliveries(scan_id);
"""


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Crea la BBDD si no existe y marca como fallidos los escaneos que
    quedaron a medias (el hilo murió con el reinicio del servicio)."""
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with _write_lock, closing(_connect()) as conn, conn:
        conn.executescript(_SCHEMA)
        conn.execute(
            "UPDATE scans SET status='failed', "
            "error='Escaneo interrumpido por reinicio del servicio' "
            "WHERE status IN ('pending', 'running')"
        )


def save_job(job):
    """Inserta o actualiza un escaneo."""
    with _write_lock, closing(_connect()) as conn, conn:
        conn.execute(
            """
            INSERT INTO scans (scan_id, created_at, target, profile, status,
                               error, events)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status=excluded.status,
                error=excluded.error,
                events=excluded.events
            """,
            (
                job["scan_id"],
                job.get("created_at") or "",
                job["target"],
                job["profile"],
                job["status"],
                job.get("error"),
                json.dumps(job.get("events", [])),
            ),
        )


def _row_to_job(row, with_events=True):
    job = {
        "scan_id": row["scan_id"],
        "created_at": row["created_at"] or None,
        "target": row["target"],
        "profile": row["profile"],
        "status": row["status"],
    }
    if row["error"]:
        job["error"] = row["error"]
    if with_events:
        job["events"] = json.loads(row["events"])
    return job


def load_job(scan_id):
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
    return _row_to_job(row) if row else None


def list_jobs(limit=100):
    """Devuelve los escaneos con todos sus eventos, del más reciente al más antiguo."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT scan_id, created_at, target, profile, status, error, events "
            "FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_job(r, with_events=True) for r in rows]


def record_event_delivery(event, status, scan_id=None):
    """Registra el estado de entrega de un evento sin alterar su contenido."""
    event_id = event.get("event_id") if isinstance(event, dict) else None
    if not event_id:
        return

    raw_event = json.dumps(event)
    with _write_lock, closing(_connect()) as conn, conn:
        existing = conn.execute(
            "SELECT attempts FROM event_deliveries WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        attempts = (existing["attempts"] if existing else 0) + 1

        conn.execute(
            """
            INSERT INTO event_deliveries (event_id, scan_id, status, attempts, event_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO UPDATE SET
                scan_id=COALESCE(excluded.scan_id, event_deliveries.scan_id),
                status=excluded.status,
                attempts=excluded.attempts,
                event_json=excluded.event_json,
                updated_at=strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            """,
            (event_id, scan_id, status, attempts, raw_event),
        )


def get_pending_events(limit=None):
    """Devuelve lista de tuplas (scan_id, event_dict) pendientes de entrega."""
    query = (
        "SELECT scan_id, event_json FROM event_deliveries "
        "WHERE status = 'pending' ORDER BY updated_at ASC"
    )
    params = ()
    if limit is not None:
        query += " LIMIT ?"
        params = (limit,)

    with closing(_connect()) as conn:
        rows = conn.execute(query, params).fetchall()

    return [(r["scan_id"], json.loads(r["event_json"])) for r in rows]


def get_delivery_summary(scan_id):
    """Devuelve resumen de estados de entrega para un escaneo."""
    summary = {
        "delivered": 0,
        "pending": 0,
        "rejected_conflict": 0,
        "rejected": 0,
    }
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS cnt FROM event_deliveries "
            "WHERE scan_id = ? GROUP BY status",
            (scan_id,),
        ).fetchall()
    for r in rows:
        st = r["status"]
        summary[st] = r["cnt"]
    return summary