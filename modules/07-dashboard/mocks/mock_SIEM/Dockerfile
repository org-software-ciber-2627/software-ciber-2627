# El contexto de construccion es la carpeta modules/07-dashboard/mocks (lo fija
# scripts/docker-compose.demo.yml), para poder copiar siem-alerts.json sin duplicarlo.
# Alpine: trae wget de busybox, que es lo que usa el healthcheck del servicio "siem" del compose.
FROM python:3.12-alpine

WORKDIR /app

COPY mock_SIEM/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mock_SIEM/app.py .
COPY siem-alerts.json .

EXPOSE 80

CMD ["python", "app.py"]
