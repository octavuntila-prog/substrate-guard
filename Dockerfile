# substrate-guard — reproducible image (tests run at build; same deps as pyproject)
# Base: Python 3.12 slim (ARM64 wheels available for z3-solver, etc.)

FROM python:3.12-slim

LABEL maintainer="Octavian Untilă <octav@aisophical.com>"
LABEL description="substrate-guard: verification stack (Z3, chain, comply, attest, offline)"

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY substrate_guard/ /app/substrate_guard/
COPY tests/ /app/tests/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev,postgres]"

ENV PYTHONPATH=/app
ENV GUARD_MODE=mock
ENV GUARD_LOG_LEVEL=INFO

# Faza 5: build fails if the suite fails (parity with CI)
RUN python -m pytest tests/ -q --tb=short

HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import substrate_guard; print(substrate_guard.__version__)"

CMD ["python", "-m", "substrate_guard.cli", "stack-benchmark"]
