# Ariadne - Attack Path Synthesizer
# Multi-stage build for smaller image size

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy files needed for building
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /app/wheels

# Production image
FROM python:3.12-slim

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash ariadne && \
    mkdir -p /app/data /home/ariadne/.ariadne && \
    chown -R ariadne:ariadne /app /home/ariadne/.ariadne

# Copy wheel from builder and install
COPY --from=builder /app/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Switch to non-root user
USER ariadne

# Set environment variables
ENV ARIADNE_HOME=/home/ariadne/.ariadne \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose web port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/health')" || exit 1

# Default command - run web server
CMD ["ariadne", "web", "--host", "0.0.0.0", "--port", "8443"]
