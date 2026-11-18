# syntax=docker/dockerfile:1
# Demo web application (Flask + Authlib). Valid as Dockerfile and Containerfile.

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
COPY app.py helpers.py ./
COPY templates ./templates
COPY static ./static
# Run as an unprivileged user.
RUN useradd --system --no-create-home app && chown -R app /app
USER app
EXPOSE 8081
CMD ["gunicorn", "--bind", "0.0.0.0:8081", "--no-control-socket", "--workers", "2", "--access-logfile", "-", "app:get_wsgi_app()"]
