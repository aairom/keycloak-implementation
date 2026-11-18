#!/usr/bin/env bash
# End-of-project cleanup: stop the stack, delete its volumes, remove node_modules, .venv, __pycache__, .run.
# Usage: scripts/cleanup.sh [--dry-run]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

if [ "$DRY" -eq 0 ]; then "$ROOT/scripts/stop.sh" --volumes || true; else echo "would stop the stack and delete its volumes"; fi

COUNT=0
while IFS= read -r p; do
  COUNT=$((COUNT+1))
  if [ "$DRY" -eq 1 ]; then echo "would remove: $p"; else rm -rf "$p"; echo "removed: $p"; fi
done < <(find "$ROOT" \( -name node_modules -o -name .venv -o -name __pycache__ -o -name .pytest_cache -o -name .run \) \
           -prune -not -path "$ROOT/.git/*" -not -path "$ROOT/.bob/*" -print)
echo "Done ($COUNT item(s), dry-run=$DRY)"
