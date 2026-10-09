import json
from pathlib import Path
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

app = FastAPI(
    title="SIEM Mock Server - Equipo 5",
    description="Simulador del contrato GET /alerts para pruebas del SOAR (Sprint 1)",
    version="1.0.0"
)

MOCK_FILE = Path(__file__).parent / "mocks" / "alerts_mock.json"

@app.get("/alerts")
def get_alerts(simulate_error: bool = Query(False, description="Simula caída del SIEM (HTTP 500)")):
    """
    Devuelve las alertas acordadas en el contrato del Sprint 1.
    Permite probar errores HTTP del servidor mediante el parámetro simulate_error.
    """
    if simulate_error:
        raise HTTPException(status_code=500, detail="Error interno simulado del SIEM (500)")

    if not MOCK_FILE.exists():
        raise HTTPException(status_code=404, detail="Fichero alerts_mock.json no encontrado")

    with open(MOCK_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return JSONResponse(content=data)