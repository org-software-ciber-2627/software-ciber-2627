FROM docker.io/python:3.14-alpine

WORKDIR /ids

COPY logs logs
COPY src src
RUN python -m venv .venv && \
    source .venv/bin/activate && \
    python -m pip install -r src/requirements.txt && \
    rm src/requirements.txt

CMD source .venv/bin/activate && cd src && python main.py
