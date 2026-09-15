FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PANDAX_DATA_DIR=/tmp/actis

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY alembic ./alembic
COPY apps/engine ./apps/engine
RUN pip install --no-cache-dir . && \
    addgroup --system --gid 10001 actis && \
    adduser --system --uid 10001 --ingroup actis --home /tmp/actis actis && \
    mkdir -p /tmp/actis /app/workspace && \
    chown -R actis:actis /tmp/actis /app/workspace

USER 10001:10001

EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','10000')+'/health/live',timeout=4)" || exit 1

CMD ["sh", "-c", "python -m alembic upgrade head && exec python -m uvicorn pandax.server:api --app-dir apps/engine --host 0.0.0.0 --port ${PORT:-10000}"]
