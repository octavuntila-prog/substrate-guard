# substrate-guard — Docker container for AI Research Agency
# Architecture: ARM64 (aarch64) compatible
# Base: Python 3.12 slim
# Memory limit: 512MB recommended

FROM python:3.12-slim

LABEL maintainer="Octavian Untilă <octav@aisophical.com>"
LABEL description="substrate-guard: eBPF → OPA → Z3 verification stack"

WORKDIR /app

# System deps for psycopg2
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

# Python deps (z3-solver has aarch64 wheels)
RUN pip install --no-cache-dir z3-solver pytest psycopg2-binary

# Copy project
COPY substrate_guard/ /app/substrate_guard/
COPY tests/ /app/tests/

# Config directory
RUN mkdir -p /app/config /var/log/substrate-guard

# Default config
COPY scripts/config_docker.json /app/config/substrate.json

# Run tests at build time to verify
RUN python -m pytest tests/ -q --tb=short

# Environment
ENV PYTHONPATH=/app
ENV GUARD_MODE=mock
ENV GUARD_LOG_LEVEL=INFO

# Health check
HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "from substrate_guard.integrations import SubstrateGuard; sg=SubstrateGuard(use_ebpf=False); h=sg.health_check(); exit(0 if h['overall']!='error' else 1)"

# Default: benchmark. Override with audit for real DB audit.
CMD ["python", "-m", "substrate_guard.combo_cli", "benchmark"]
