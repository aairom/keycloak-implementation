# syntax=docker/dockerfile:1
# Demo REST API (Flask resource server). Valid as Dockerfile and Containerfile.

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
COPY api_app.py api_auth.py ./
# Run as an unprivileged user.
RUN useradd --system --no-create-home app && chown -R app /app
USER app
EXPOSE 8082
CMD ["gunicorn", "--bind", "0.0.0.0:8082", "--workers", "2", "--access-logfile", "-", "api_app:create_app()"]
