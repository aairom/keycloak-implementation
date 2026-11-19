#!/usr/bin/env bash
# Run connector/examples/flask_app.py against the demo stack, using the registered demo-logapp client.
# That client only allows http://localhost:8083/callback, so the log dashboard container (same port) is stopped
# while the example runs and started again when you press Ctrl+C. Variables come from .env; nothing is printed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -f .env ] || { echo "No .env found: run scripts/init-env.sh first." >&2; exit 1; }
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || { echo "No .venv: run  uv venv && uv pip install -r requirements.txt" >&2; exit 1; }
set -a; . ./.env; set +a

# Another running example (or any Python app) on 8083 would make the start fail: stop before changing anything.
if lsof -nP -iTCP:8083 -sTCP:LISTEN 2>/dev/null | grep -qi python; then
  echo "Port 8083 is already used by a running Python app (probably another run of this script)." >&2
  echo "Stop it first (Ctrl+C in its terminal); that also starts the log dashboard again." >&2
  exit 1
fi

ENGINE=""; command -v podman >/dev/null && ENGINE=podman; [ -z "$ENGINE" ] && command -v docker >/dev/null && ENGINE=docker
LOGAPP="$(${ENGINE:-true} ps --format '{{.Names}}' 2>/dev/null | grep -E 'logapp' | head -1 || true)"
APP_PID=""
restore() {
  trap - EXIT INT TERM
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null && wait "$APP_PID" 2>/dev/null || true
  if [ -n "$LOGAPP" ]; then "$ENGINE" start "$LOGAPP" >/dev/null && echo "Log dashboard started again."; fi
}
trap restore EXIT
trap "exit 130" INT TERM
if [ -n "$LOGAPP" ]; then
  echo "Stopping the log dashboard ($LOGAPP) to free port 8083 ..."
  "$ENGINE" stop "$LOGAPP" >/dev/null
fi

export KEYCLOAK_SERVER_URL="$KC_HOSTNAME" KEYCLOAK_REALM="${DEMO_REALM:-demo}" KEYCLOAK_CLIENT_ID=demo-logapp
export KEYCLOAK_CLIENT_SECRET="$LOGAPP_CLIENT_SECRET" KEYCLOAK_REDIRECT_URI=http://localhost:8083/callback
export KEYCLOAK_POST_LOGOUT_REDIRECT_URI=http://localhost:8083/ PORT=8083
echo "Example running: open http://localhost:8083/ and sign in as alice or bob (passwords: DEMO_USER_PASSWORD / DEMO_ADMIN_PASSWORD in .env). Ctrl+C to stop."
# Run in the background and wait, so a signal sent to this script also stops the app and restores the dashboard.
"$PY" connector/examples/flask_app.py &
APP_PID=$!
wait "$APP_PID" || true
