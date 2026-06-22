# substrate-guard — image with tests run at build (same deps as pyproject).
# Base: Python 3.12 slim (ARM64 wheels available for z3-solver, etc.). NOTE: the base
# is tracked by tag, not digest-pinned -- pin to a sha256 digest for byte-reproducibility.

FROM python:3.12-slim

LABEL maintainer="Octavian Untilă <octav@aisophical.com>"
LABEL description="substrate-guard: verification stack (Z3, chain, comply, attest, offline)"

WORKDIR /app

COPY pyproject.toml README.md bandit.yaml /app/
COPY substrate_guard/ /app/substrate_guard/
COPY tests/ /app/tests/
COPY examples/ /app/examples/
# scripts/ and docs/deploy-verification/ are test fixtures: the ops-script tests
# read/execute scripts/*.sh, and the drift-guard tests read the smoke JSONs. Without
# these the build-time pytest (below) fails on missing fixtures in the Linux image
# while skipping/passing on a Windows dev host.
COPY scripts/ /app/scripts/
COPY docs/deploy-verification/ /app/docs/deploy-verification/

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev,postgres]"

ENV PYTHONPATH=/app
ENV GUARD_MODE=mock
ENV GUARD_LOG_LEVEL=INFO

# Faza 5: build fails if the suite fails (parity with CI)
RUN python -m pytest tests/ -q --tb=short

# Run as a non-root user (the audited image ran everything as root).
RUN useradd --create-home --uid 10001 guard && chown -R guard:guard /app
USER guard

HEALTHCHECK --interval=60s --timeout=10s --retries=3 \
    CMD python -c "import substrate_guard; print(substrate_guard.__version__)"

CMD ["python", "-m", "substrate_guard.cli", "stack-benchmark"]
