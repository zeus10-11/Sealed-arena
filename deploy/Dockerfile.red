# ============================================================================
# Sealed Arena — Red Zone Dockerfile
# ============================================================================
# The Red Zone is the attack environment. It can ONLY communicate with the
# Referee via the red-net network. It has no internet access and no
# visibility into Blue Zone or Model Zone.
#
# Build: docker build -f deploy/Dockerfile.red -t sealed-arena-red .
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build dependencies
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Runtime image (minimal, locked down)
# ---------------------------------------------------------------------------
FROM python:3.14-slim AS runtime

# Security: run as non-root user
RUN groupadd -r arena && \
    useradd -r -g arena -d /app -s /sbin/nologin arena

COPY --from=builder /install /usr/local

WORKDIR /app

# Copy only the red zone agent source
COPY src/zones/red/ ./src/zones/red/
COPY src/common/ ./src/common/

# No volumes — red zone has no persistent storage
# No shared directories — prevents filesystem-based leakage

USER arena

# Health check: verify connectivity to Referee
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=15s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://referee:8000/health')"

# Run the Red Zone agent
ENTRYPOINT ["python", "-m"]
CMD ["src.zones.red.agent"]
