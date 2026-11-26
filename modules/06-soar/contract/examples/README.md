# Ejemplos de respuestas del SOAR

Generados con la API real por `tests/test_contract_examples.py`: un incidente de fuerza bruta en
`contained`, sin `GROUP7_NOTIFY_URL`, como en la demo. Los ids y las fechas se fijan a valores de ejemplo.
El test comprueba que tienen las mismas claves que la API; se regeneran con `SOAR_WRITE_EXAMPLES=1`.

- `incidents.json`: respuesta de `GET /incidents` (con `credential` y `username` enmascarados como `***`).
- `history.json`: respuesta de `GET /incidents/{incident_id}/history` de ese incidente.
- `responses.json`: respuesta de `GET /incidents/{incident_id}/responses` de ese incidente.
