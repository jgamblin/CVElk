# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir hatch

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build the wheel
RUN hatch build -t wheel

# Runtime stage
FROM python:3.11-slim

# Create non-root user
RUN useradd --create-home --shell /bin/bash cvelk

# Set working directory
WORKDIR /app

# Install the wheel from builder stage
COPY --from=builder /app/dist/*.whl ./
RUN pip install --no-cache-dir ./*.whl && rm -f ./*.whl

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
