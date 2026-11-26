from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import app as soar_app


def test_get_metrics_returns_four_fields_for_empty_database(tmp_path: Path) -> None:
    database_path = str(tmp_path / "metrics.db")
    with patch.object(soar_app, "DATABASE_PATH", database_path):
        server = ThreadingHTTPServer(("127.0.0.1", 0), soar_app.SoarHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/metrics"
            with urllib.request.urlopen(url) as response:
                assert response.status == 200
                payload = json.loads(response.read().decode("utf-8"))

            assert payload == {
                "mttd_seconds": None,
                "mttr_seconds": None,
                "total_incidents": 0,
                "closed_incidents": 0,
            }
            assert set(payload) == {
                "mttd_seconds",
                "mttr_seconds",
                "total_incidents",
                "closed_incidents",
            }
        finally:
            server.shutdown()
            server.server_close()
