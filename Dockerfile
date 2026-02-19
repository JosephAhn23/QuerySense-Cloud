# QuerySense — PostgreSQL query performance analyzer
# Multi-stage build for minimal image size
#
# Usage:
#   docker build -t querysense .
#   docker run --rm -v $(pwd)/plans:/plans querysense ci gate "plans/*.json"
#   docker run --rm -v $(pwd)/plan.json:/plan.json querysense analyze /plan.json

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /dist

# ── Runtime stage ───────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="QuerySense"
LABEL org.opencontainers.image.description="PostgreSQL query performance analyzer"
LABEL org.opencontainers.image.source="https://github.com/JosephAhn23/Query-Sense"
LABEL org.opencontainers.image.licenses="MIT"

# Install from wheel built in builder stage
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -f /tmp/*.whl

# Non-root user for security
RUN useradd --create-home --shell /bin/bash querysense
USER querysense
WORKDIR /workspace

ENTRYPOINT ["querysense"]
CMD ["--help"]
