# Use an official lightweight Python runtime
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy the official Linux cosign binary into the container
COPY --from=ghcr.io/sigstore/cosign/cosign:v2.4.1 /ko-app/cosign /usr/local/bin/cosign

# Install dependencies first for optimal Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy webhook application source code and generated TLS certificates
COPY webhook/ ./webhook/
COPY certs/ ./certs/
COPY evidence/ /evidence/

# Expose HTTPS port used by the admission server
EXPOSE 8443

# Start the webhook server via Uvicorn
CMD ["uvicorn", "webhook.main:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-keyfile", "certs/server.key", "--ssl-certfile", "certs/server.crt"]
