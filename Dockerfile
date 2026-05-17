FROM python:3.12-slim

LABEL maintainer="security-team"
LABEL description="Cloud Asset Security Review — ephemeral scan worker"

# Security: run as non-root
RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ ./src/

# Writable dirs for DB and reports (mounted as volumes in prod)
RUN mkdir -p /tmp/reports /tmp/db && \
    chown -R scanner:scanner /app /tmp/reports /tmp/db

USER scanner

ENV DB_PATH=/tmp/db/asset_registry.db
ENV REPORTS_OUTPUT_DIR=/tmp/reports
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default: run as a single-asset scan worker
# Override CMD for different modes:
#   docker run ... python -m src.main demo --target example.com
#   docker run ... python -m src.main worker --once
ENTRYPOINT ["python", "-m"]
CMD ["src.main", "worker", "--once"]
