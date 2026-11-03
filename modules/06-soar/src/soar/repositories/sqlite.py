import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager


@contextmanager
def connect(database_path: str) -> Iterator[sqlite3.Connection]:
    """
    Abre una conexión al SQLite del módulo (el mismo DATABASE_PATH que usa app.py),
    confirma la transacción si no hay errores y siempre cierra la conexión.
    """
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()
