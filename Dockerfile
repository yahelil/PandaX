# syntax=docker/dockerfile:1.7
# Immutable manifests with readable version tags.
FROM eclipse-temurin:21.0.11_10-jre-jammy@sha256:d63bd8d9b171999cbed8576f2c76e874dd4856791a358536e5c4d407e77edc13 AS java
FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_CACHE_DIR=/tmp/uv-cache \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/java/openjdk/bin:/app/.venv/bin:$PATH
WORKDIR /app

COPY --from=java /opt/java/openjdk /opt/java/openjdk
COPY pyproject.toml uv.lock README.md ./
COPY apps/engine ./apps/engine
COPY apps/verifier ./apps/verifier
COPY tools/bootstrap.py tools/setup_verapdf.py ./tools/

# uv is build-only. --locked makes dependency drift fatal; --no-editable
# leaves a self-contained application installation for the runtime stage.
RUN python -m pip install --no-cache-dir uv==0.12.8 \
    && uv sync --locked --no-dev --no-editable --package actis \
    && python -c "from tools.bootstrap import install_syft; install_syft()" \
    && python tools/setup_verapdf.py \
    && rm -rf "$UV_CACHE_DIR"

FROM python:3.12.14-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254 AS runtime

ARG RENDER_GIT_COMMIT=unknown

LABEL org.opencontainers.image.title="Actis by PandaX API" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.revision="${RENDER_GIT_COMMIT}" \
      org.opencontainers.image.source="https://github.com/yahelil/PandaX"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/apps/engine \
    PATH=/app/.venv/bin:/opt/java/openjdk/bin:$PATH \
    JAVA_HOME=/opt/java/openjdk \
    PANDAX_ENVIRONMENT=beta \
    PANDAX_DATA_DIR=/tmp/actis/data \
    PANDAX_VERAPDF=/app/workspace/tools/verapdf/bin/cli-1.30.2.jar \
    RENDER_GIT_COMMIT=${RENDER_GIT_COMMIT}
WORKDIR /app

COPY --from=java /opt/java/openjdk /opt/java/openjdk
COPY --from=build /app/.venv /app/.venv
COPY --from=build /app/workspace/tools /app/workspace/tools
COPY apps/engine ./apps/engine
COPY tools/beta_release.py tools/container_smoke.py ./tools/
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic

RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin actis \
    && mkdir -p /tmp/actis/data /app/workspace/runs /app/workspace/cache \
    && chown -R actis:actis /tmp/actis /app/workspace \
    && python -c "from pandax.artifact_runtime import require_hosted_scanner; print(require_hosted_scanner())" \
    && python -c "from pandax.document_runtime import require_hosted_document_tools; print(require_hosted_document_tools())"

USER 10001:65534
EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn pandax.server:api --host 0.0.0.0 --port \"${PORT:-10000}\" --workers 1 --proxy-headers --forwarded-allow-ips='*'"]
