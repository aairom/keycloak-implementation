# syntax=docker/dockerfile:1
# Log dashboard (Flask + Authlib + psycopg). Valid as Dockerfile and Containerfile.

# ---- Build stage: resolve and install dependencies ----
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- Runtime stage ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=build /install /usr/local
COPY log_app.py event_sync.py log_config.py log_helpers.py store.py token_source.py ./
COPY templates ./templates
COPY static ./static
# Run as an unprivileged user.
RUN useradd --system --no-create-home app && chown -R app /app
USER app
EXPOSE 8083
# One worker process: tokens live in process memory (see app.py). Concurrency comes from threads.
CMD ["gunicorn", "--bind", "0.0.0.0:8083", "--no-control-socket", "--workers", "1", "--threads", "8", "--access-logfile", "-", "log_app:get_wsgi_app()"]
