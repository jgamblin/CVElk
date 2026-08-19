# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

# pip runs as root inside the image on purpose; silence its venv nag
ENV PIP_ROOT_USER_ACTION=ignore

# Install build dependencies
RUN pip install --no-cache-dir hatch

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build the wheel
RUN hatch build -t wheel

# Runtime stage
FROM python:3.12-slim

ENV PIP_ROOT_USER_ACTION=ignore

# Upgrade OS packages to pick up security fixes (e.g. liblzma5 CVE-2026-34743)
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash cvelk

# Set working directory
WORKDIR /app

# Install the wheel from builder stage, then remove the installer toolchain.
# Nothing in this image needs pip at run time, and pip ships vendored copies of
# setuptools and msgpack (see pip/_vendor/vendor.txt) that Trivy reports as
# CVE-2025-47273, CVE-2026-59890 and GHSA-6v7p-g79w-8964. Those pins are frozen
# upstream, so removing pip is the only real remediation.
COPY --from=builder /app/dist/*.whl ./
RUN pip install --no-cache-dir ./*.whl \
    && rm -f ./*.whl \
    && pip uninstall -y pip setuptools wheel

# Create data directory
RUN mkdir -p /app/data && chown cvelk:cvelk /app/data

# Copy dashboard resources
COPY --chown=cvelk:cvelk src/cvelk/resources/ ./resources/

# Switch to non-root user
USER cvelk

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DATA_DIR=/app/data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from cvelk import __version__; print(__version__)" || exit 1

# Default command
ENTRYPOINT ["cvelk"]
CMD ["--help"]
