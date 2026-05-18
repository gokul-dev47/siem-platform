FROM python:3.11-slim

LABEL maintainer="Gokul - SIEM Project"
LABEL description="SIEM Backend v1.2 - Flask + WebSocket + Alerting Engine"

WORKDIR /app

# curl is required for the HEALTHCHECK below
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /var/log/siem

EXPOSE 8000

# start-period=60s gives gunicorn + the _boot() wait thread time to
# initialise before Docker starts counting failed health checks.
# On WSL2/Windows this needs to be generous.
HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["gunicorn", \
     "--worker-class", "eventlet", \
     "-w", "1", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--log-level", "info", \
     "app:app"]
