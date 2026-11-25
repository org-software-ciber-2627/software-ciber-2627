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