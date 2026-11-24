import sqlite3
from typing import Iterable, Optional

from soar.models.blacklist_entry import BlacklistEntry
from soar.repositories.sqlite import connect


class DuplicateIpError(Exception):
    """La IP ya está en la lista negra; la entrada original no se toca."""


class BlacklistRepository:
    def __init__(self, entries: Iterable[BlacklistEntry] = ()) -> None:
        self._entries: dict[str, BlacklistEntry] = {}
        for entry in entries:
            self.add(entry)

    def add(self, entry: BlacklistEntry) -> BlacklistEntry:
        if entry.ip in self._entries:
            raise DuplicateIpError(entry.ip)
        self._entries[entry.ip] = entry
        return entry

    def get_by_ip(self, ip: str) -> Optional[BlacklistEntry]:
        return self._entries.get(ip)

    def list_all(self) -> list[BlacklistEntry]:
        return list(self._entries.values())


class SqliteBlacklistRepository:
    """
    Misma interfaz que BlacklistRepository, persistida en la tabla ip_blacklist.
    La IP es la clave primaria, así que SQLite impide los duplicados.
    """

    def __init__(self, database_path: str) -> None:
        self._database_path = database_path
        with connect(database_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ip_blacklist (
                    ip TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    entry_json TEXT NOT NULL
                )
                """
            )

    def add(self, entry: BlacklistEntry) -> BlacklistEntry:
        try:
            with connect(self._database_path) as connection:
                connection.execute(
                    "INSERT INTO ip_blacklist (ip, incident_id, entry_json) VALUES (?, ?, ?)",
                    (entry.ip, entry.incident_id, entry.model_dump_json()),
                )
        except sqlite3.IntegrityError as error:
            raise DuplicateIpError(entry.ip) from error
        return entry

    def get_by_ip(self, ip: str) -> Optional[BlacklistEntry]:
        with connect(self._database_path) as connection:
            row = connection.execute("SELECT entry_json FROM ip_blacklist WHERE ip = ?", (ip,)).fetchone()
        return BlacklistEntry.model_validate_json(row["entry_json"]) if row else None

    def list_all(self) -> list[BlacklistEntry]:
        with connect(self._database_path) as connection:
            rows = connection.execute("SELECT entry_json FROM ip_blacklist ORDER BY rowid").fetchall()
        return [BlacklistEntry.model_validate_json(row["entry_json"]) for row in rows]
