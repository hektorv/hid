# One image for the backend and the validator; build from the repository root:
#   docker build -f bola-gateway/Dockerfile .
FROM python:3.12-slim
WORKDIR /app
COPY huuid /app/huuid
COPY bola-gateway/pyproject.toml /app/bola-gateway/pyproject.toml
COPY bola-gateway/src /app/bola-gateway/src
RUN pip install --no-cache-dir /app/huuid /app/bola-gateway \
    && useradd --create-home lab
USER lab
WORKDIR /home/lab
