FROM python:3.12-slim

WORKDIR /app

COPY app.py .

RUN pip install Flask

EXPOSE 5002

CMD ["python", "app.py"]
