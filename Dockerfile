# syntax=docker/dockerfile:1

# Certificate Expiry Monitor (CEM) container image.
#
# Build:   docker build -t cem .
# Run:     docker run --rm -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
#           -v cem-state:/app/data cem check --config /app/config.yaml \
#           --state-file /app/data/certificate-monitor-state.json

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install runtime dependencies first so this layer is cached across rebuilds.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and sample config.
COPY checker/ ./checker/
COPY example_config.yaml ./

# Run as an unprivileged user. /app/data is the persistent state/cert volume.
RUN useradd --create-home --shell /usr/sbin/nologin cem \
    && mkdir -p /app/data \
    && chown -R cem:cem /app

USER cem

VOLUME ["/app/data"]

# HTTP API server port (serve mode).
EXPOSE 8000

ENTRYPOINT ["python", "-m", "checker"]
CMD ["check"]
