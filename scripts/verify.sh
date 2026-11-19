#!/usr/bin/env bash
# End-to-end verification of a running deployment (local or online). Exit 0 = every check passed.
# Usage: scripts/verify.sh
# Human-user checks need DEMO_CLI_ENABLED=true (password grant client "demo-cli"); service checks need SERVICE_CLIENT_SECRET.
# Requires curl + python3; the log dashboard checks also need the python package 'requests' (.venv from requirements.txt).
# Reads KC_HOSTNAME, API_PUBLIC_URL, WEBAPP_PUBLIC_URL, LOGAPP_PUBLIC_URL, DEMO_REALM and the demo passwords from .env.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$ROOT/.env" ]; then set -a; . "$ROOT/.env"; set +a; fi

KC="${KC_HOSTNAME:?KC_HOSTNAME not set (create .env first)}"
REALM="${DEMO_REALM:-demo}"
API="${API_PUBLIC_URL:-http://localhost:8082}"
APP="${WEBAPP_PUBLIC_URL:-http://localhost:8081}"
FAIL=0
# Extra curl options, e.g. VERIFY_CURL_OPTS="-k" to accept a self-signed certificate in tests.
curl() { command curl ${VERIFY_CURL_OPTS:-} "$@"; }

ok()   { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; FAIL=1; }
# expect <description> <expected-http-code> <actual-http-code>
expect() { if [ "$2" = "$3" ]; then ok "$1 (HTTP $3)"; else bad "$1 (expected $2, got $3)"; fi; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }
json() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))"; }
token() { # $1 user $2 password
  curl -s --max-time 15 -d grant_type=password -d client_id=demo-cli -d "username=$1" --data-urlencode "password=$2" \
    "$KC/realms/$REALM/protocol/openid-connect/token" | json access_token
}

echo "== Keycloak ($KC), realm '$REALM'"
expect "OIDC discovery document" 200 "$(code "$KC/realms/$REALM/.well-known/openid-configuration")"
expect "realm signing keys (JWKS)" 200 "$(code "$KC/realms/$REALM/protocol/openid-connect/certs")"
expect "login page of the web app client renders" 200 \
  "$(code -L "$KC/realms/$REALM/protocol/openid-connect/auth?client_id=demo-webapp&response_type=code&scope=openid&redirect_uri=$APP/callback")"

echo "== Web app ($APP)"
expect "health endpoint" 200 "$(code "$APP/healthz")"
loc="$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 15 "$APP/login")"
case "$loc" in *code_challenge_method=S256*) ok "login redirects to Keycloak with PKCE (S256)";; *) bad "login redirect missing PKCE: $loc";; esac

echo "== API ($API)"
expect "public health endpoint" 200 "$(code "$API/api/health")"
expect "no token is rejected" 401 "$(code "$API/api/reports")"
expect "garbage token is rejected" 401 "$(code -H 'Authorization: Bearer abc.def.ghi' "$API/api/reports")"

ALICE="$(token alice "${DEMO_USER_PASSWORD:-}")"; BOB="$(token bob "${DEMO_ADMIN_PASSWORD:-}")"
if [ -z "$ALICE" ] || [ -z "$BOB" ]; then
  bad "could not obtain tokens (is DEMO_CLI_ENABLED=true and are the .env passwords the imported ones?)"
else
  ok "obtained access tokens for alice and bob"
  echo "== Authorization (roles evaluated by Keycloak policies)"
  expect "alice GET  /api/me" 200 "$(code -H "Authorization: Bearer $ALICE" "$API/api/me")"
  expect "alice GET  /api/reports (app-user)" 200 "$(code -H "Authorization: Bearer $ALICE" "$API/api/reports")"
  expect "alice POST /api/reports (needs app-admin)" 403 "$(code -X POST -H "Authorization: Bearer $ALICE" "$API/api/reports")"
  expect "alice GET  /api/admin (needs app-admin)" 403 "$(code -H "Authorization: Bearer $ALICE" "$API/api/admin")"
  expect "bob   GET  /api/reports" 200 "$(code -H "Authorization: Bearer $BOB" "$API/api/reports")"
  expect "bob   POST /api/reports" 201 "$(code -X POST -H "Authorization: Bearer $BOB" "$API/api/reports")"
  expect "bob   GET  /api/admin" 200 "$(code -H "Authorization: Bearer $BOB" "$API/api/admin")"
fi

echo "== Service-to-service (client credentials, no user)"
svc_token() {
  curl -s --max-time 15 -d grant_type=client_credentials -d client_id=demo-service \
    --data-urlencode "client_secret=${SERVICE_CLIENT_SECRET:-}" "$KC/realms/$REALM/protocol/openid-connect/token" | json access_token
}
SVC="$(svc_token)"
if [ -z "$SVC" ]; then
  bad "could not obtain a service token (check SERVICE_CLIENT_SECRET)"
else
  ok "obtained service token via client credentials"
  expect "service GET /api/service/data (role app-service)" 200 "$(code -H "Authorization: Bearer $SVC" "$API/api/service/data")"
  expect "service GET /api/reports (human-only resource)" 403 "$(code -H "Authorization: Bearer $SVC" "$API/api/reports")"
  expect "service GET /api/admin (human-only resource)" 403 "$(code -H "Authorization: Bearer $SVC" "$API/api/admin")"
  [ -n "${ALICE:-}" ] && expect "alice GET /api/service/data (not a service)" 403 "$(code -H "Authorization: Bearer $ALICE" "$API/api/service/data")"
fi
expect "wrong service secret is refused" 401 "$(code -d grant_type=client_credentials -d client_id=demo-service -d client_secret=wrong "$KC/realms/$REALM/protocol/openid-connect/token")"
expect "service-to-service without token is rejected" 401 "$(code "$API/api/service/data")"

echo "== Log dashboard (scripted browser session: Keycloak login form, dashboard, filters, admin panel)"
PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY=python3
if "$PY" -c 'import requests' 2>/dev/null; then
  if [ -n "${VERIFY_CURL_OPTS:-}" ]; then export VERIFY_INSECURE=1; fi
  "$PY" "$ROOT/scripts/verify_logapp.py" | sed '1d;/^$/d;/LOGAPP VERIFY/d' | tee /tmp/.verify_logapp.$$
  grep -q '^FAIL' /tmp/.verify_logapp.$$ && FAIL=1
  [ -s /tmp/.verify_logapp.$$ ] || bad "log dashboard checks produced no output"
  rm -f /tmp/.verify_logapp.$$
else
  bad "python package 'requests' missing: run  uv venv && uv pip install -r requirements.txt"
fi

echo "== Keycloak connector (connector/: discovery, Authorization Code + PKCE, validation, refresh, logout)"
if "$PY" -c 'import requests, jwt' 2>/dev/null; then
  "$PY" "$ROOT/scripts/verify_connector.py" | sed '1d;/^$/d;/CONNECTOR VERIFY/d' | tee /tmp/.verify_connector.$$
  grep -q '^FAIL' /tmp/.verify_connector.$$ && FAIL=1
  [ -s /tmp/.verify_connector.$$ ] || bad "connector checks produced no output"
  rm -f /tmp/.verify_connector.$$
else
  bad "python packages 'requests' and 'PyJWT' missing: run  uv venv && uv pip install -r requirements.txt"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "VERIFY OK"; else echo "VERIFY FAILED"; fi
exit "$FAIL"
