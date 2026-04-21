FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

RUN mkdir -p /app/data /app/logs

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD curl -fsS http://localhost:8080/healthz || exit 1

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8080"]
