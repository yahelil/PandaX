FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/apps/engine \
    PANDAX_ENVIRONMENT=beta
WORKDIR /app

COPY pyproject.toml README.md ./
COPY apps/engine ./apps/engine
COPY tools/bootstrap.py ./tools/bootstrap.py
COPY alembic.ini ./alembic.ini
COPY alembic ./alembic

RUN python -m pip install --no-cache-dir . \
    && python -c "from tools.bootstrap import install_syft; install_syft()" \
    && useradd --system --uid 10001 --home-dir /app actis \
    && mkdir -p workspace/runs workspace/cache workspace/data \
    && chown -R actis:actis workspace

USER actis
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn pandax.server:api --host 0.0.0.0 --port ${PORT:-8000}"]
