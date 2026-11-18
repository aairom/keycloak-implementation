#!/usr/bin/env bash
# Gracefully stop the stack (containers are stopped, then removed; data volumes are kept).
# Usage: scripts/stop.sh [--prod] [--volumes]    (--volumes also deletes the database volume)
set -euo pipefail
ARGS=()
for a in "$@"; do
  case "$a" in --prod) export MODE=prod;; --volumes) ARGS+=(--volumes);; *) echo "unknown option: $a" >&2; exit 2;; esac
done
. "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# Compose needs every ${VAR:?} defined even for 'down'; fall back to the example file without a .env.
ENVFILE=(); [ -f .env ] || ENVFILE=(--env-file .env.example)
"${COMPOSE[@]}" ${ENVFILE[@]+"${ENVFILE[@]}"} down --timeout "${STOP_TIMEOUT:-30}" ${ARGS[@]+"${ARGS[@]}"}
echo "Stack stopped"
