FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSL https://github.com/sigstore/cosign/releases/download/v3.0.2/cosign-linux-amd64 -o /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY webhook/ ./webhook/
COPY certs/ ./certs/
COPY evidence/ /evidence/

EXPOSE 8443

CMD ["uvicorn", "webhook.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "certs/server.key", "--ssl-certfile", "certs/server.crt"]
