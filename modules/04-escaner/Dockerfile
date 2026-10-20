FROM python:3.12-slim

# Evita .pyc y fuerza logs sin buffer
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# nmap (necesario si runner.py lo invoca por subprocess)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencias primero para aprovechar la caché de capas
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código de la aplicación
COPY main.py runner.py jobs.py parser.py ./

EXPOSE 8004

CMD ["python", "main.py"]