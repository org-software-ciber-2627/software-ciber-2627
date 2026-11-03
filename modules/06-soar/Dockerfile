FROM python:3.12-slim

WORKDIR /app
COPY src/ /app/

RUN mkdir -p /data

EXPOSE 80
CMD ["python", "app.py"]
