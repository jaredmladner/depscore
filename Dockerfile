# ── Stage 1: build wheel ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir hatchling

COPY pyproject.toml .
COPY src/ src/

RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user
RUN useradd --create-home --shell /bin/bash depscore

WORKDIR /home/depscore

# Install runtime dependencies + the built wheel
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

# Output directory (bind-mount or volume here in production)
RUN mkdir -p /output && chown depscore:depscore /output

USER depscore

# Environment variable placeholders — supply real values at runtime
ENV GITHUB_TOKEN=""
ENV ANTHROPIC_API_KEY=""
ENV LIBRARIES_IO_API_KEY=""
ENV DEPSCORE_AI_ENABLED="true"
ENV DEPSCORE_AI_BLEND_WEIGHT="0.6"
ENV DEPSCORE_CONCURRENCY_LIMIT="10"

VOLUME ["/sbom", "/output"]

ENTRYPOINT ["depscore"]
CMD ["--help"]
