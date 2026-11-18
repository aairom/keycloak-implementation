#!/usr/bin/env bash
# Build and start the whole stack detached, wait until it is healthy and print the URLs.
# Usage: scripts/start.sh [--prod]      (--prod = online deployment with HTTPS reverse proxy)
set -euo pipefail
[ "${1:-}" = "--prod" ] && export MODE=prod
. "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

[ -f .env ] || { echo "No .env found - generating one"; scripts/init-env.sh; . ./.env; }

# Port 5000 is reserved for AirDrop on macOS.
for p in "${KEYCLOAK_PORT:-8080}" "${WEBAPP_PORT:-8081}" "${API_PORT:-8082}" "${LOGAPP_PORT:-8083}"; do
  [ "$p" = "5000" ] && [ "$(uname -s)" = "Darwin" ] && { echo "ERROR: port 5000 is reserved by AirDrop" >&2; exit 1; }
done

echo "Starting stack (mode=${MODE:-local}) with: ${COMPOSE[*]}"
"${COMPOSE[@]}" up -d --build

echo "Waiting for services to become healthy (first start takes about a minute)..."
deadline=$((SECONDS + ${START_TIMEOUT:-300}))
until curl -fsS "http://127.0.0.1:${KEYCLOAK_PORT:-8080}/realms/${DEMO_REALM:-demo}/.well-known/openid-configuration" >/dev/null 2>&1 \
   && curl -fsS "http://127.0.0.1:${WEBAPP_PORT:-8081}/healthz" >/dev/null 2>&1 \
   && curl -fsS "http://127.0.0.1:${LOGAPP_PORT:-8083}/healthz" >/dev/null 2>&1; do
  [ "$SECONDS" -lt "$deadline" ] || { echo "ERROR: timed out; see '${COMPOSE[*]} logs'" >&2; exit 1; }
  sleep 3
done

echo
echo "Stack is up."
echo "URL: ${WEBAPP_PUBLIC_URL}   (demo web app)"
echo "Keycloak:       ${KC_HOSTNAME}   (admin console: ${KC_HOSTNAME}/admin, user ${KC_BOOTSTRAP_ADMIN_USERNAME})"
echo "Log dashboard: ${LOGAPP_PUBLIC_URL:-http://localhost:8083}   (sign in as bob for the admin panel)"
echo "API health:     ${API_PUBLIC_URL:-http://localhost:8082}/api/health"
echo "Verify:         scripts/verify.sh"
