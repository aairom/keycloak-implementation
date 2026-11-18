#!/usr/bin/env bash
# Create .env from .env.example with freshly generated random secrets (never overwrites an existing .env).
# Usage: scripts/init-env.sh [--force]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -f .env ] && [ "${1:-}" != "--force" ]; then echo ".env already exists (use --force to regenerate)"; exit 0; fi
[ -f .env.example ] || { echo "ERROR: .env.example not found" >&2; exit 1; }

# openssl avoids the SIGPIPE that 'tr | head' raises under pipefail; hex output is URL/sed safe.
rand() { openssl rand -hex "$(( ${1:-24} / 2 ))"; }

cp .env.example .env
# Replace every "changeme-*" placeholder by a random value (portable sed: write to a temp file).
while IFS= read -r key; do
  value="$(rand 24)"
  sed "s|^${key}=.*|${key}=${value}|" .env > .env.tmp && mv .env.tmp .env
done < <(grep -E '^[A-Z_]+=changeme' .env.example | cut -d= -f1)
chmod 600 .env
echo "Created .env with generated secrets. Review it, then run scripts/start.sh"
echo "Demo logins: alice / bob - passwords are DEMO_USER_PASSWORD / DEMO_ADMIN_PASSWORD in .env"
