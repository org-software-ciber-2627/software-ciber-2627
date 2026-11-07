FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY src/ /app/

RUN mkdir -p /data

EXPOSE 80
CMD ["python", "app.py"]
