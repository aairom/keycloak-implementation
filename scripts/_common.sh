#!/usr/bin/env bash
# Shared helpers: pick the container engine, compose command and load .env. Sourced by the other scripts.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -f .env ]; then set -a; . ./.env; set +a; fi

# Compose command: honour COMPOSE_CMD, else podman (preferred, local runtime) then docker.
if [ -z "${COMPOSE_CMD:-}" ]; then
  if command -v podman >/dev/null 2>&1; then COMPOSE_CMD="podman compose"
  elif command -v docker >/dev/null 2>&1; then COMPOSE_CMD="docker compose"
  else echo "ERROR: install Podman or Docker (with the compose plugin)" >&2; exit 1; fi
fi

# MODE=prod adds the HTTPS reverse-proxy overlay.
COMPOSE_FILES=(-f docker-compose.yml)
if [ "${MODE:-local}" = "prod" ]; then COMPOSE_FILES+=(-f docker-compose.prod.yml); fi
# shellcheck disable=SC2206
COMPOSE=($COMPOSE_CMD "${COMPOSE_FILES[@]}")
