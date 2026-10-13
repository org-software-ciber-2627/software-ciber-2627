FROM python:3.12-slim

WORKDIR /app

# curl y wget requeridos por el docker-compose de la clase
RUN apt-get update && apt-get install -y curl wget && rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

ENV FLASK_APP=app.py

EXPOSE 80

CMD ["gunicorn", "--preload", "-w", "2", "-b", "0.0.0.0:80", "app:app"]