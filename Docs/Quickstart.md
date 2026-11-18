# Quickstart (local)

Goal: a working Keycloak with a login-protected web app and API in about three minutes of attended time
(plus the image build on first run).

## 1. Prerequisites

| Tool | Version | Check |
|---|---|---|
| Podman **or** Docker, with the compose plugin | Podman 5+/Docker 24+ | `podman compose version` or `docker compose version` |
| curl, python3, openssl | any recent | used by the helper scripts |
| Free ports | 8080 (Keycloak), 8081 (web app), 8082 (API) | `lsof -i :8080 -i :8081 -i :8082` |

macOS with Podman: start the VM first (`podman machine start`). Port 5000 is never used (AirDrop).
The scripts pick Podman first and fall back to Docker; force one with `COMPOSE_CMD="docker compose" scripts/start.sh`.

## 2. Start

```bash
git clone <this repository> keycloak-implementation && cd keycloak-implementation
scripts/start.sh
```

On the first run the script:

1. creates `.env` from `.env.example` with random secrets (`scripts/init-env.sh`),
2. builds three images (Keycloak with theme and realm, API, web app) and pulls PostgreSQL,
3. waits until Keycloak and the web app answer, then prints the URLs.

Expect 1-3 minutes on first start (image pulls and Keycloak build step); later starts take under a minute.
The Keycloak realm `demo` is imported automatically on first start only.

## 3. Take the tour

Show your passwords: `grep -E 'DEMO_(USER|ADMIN)_PASSWORD|KC_BOOTSTRAP' .env`. There are two separate kinds of account:

| Account | Realm | Sign in at | Username | Password in `.env` |
|---|---|---|---|---|
| Demo user (employee) | `demo` | web app <http://localhost:8081> | `alice` | `DEMO_USER_PASSWORD` |
| Demo user (manager, **not** a Keycloak admin) | `demo` | web app <http://localhost:8081> | `bob` | `DEMO_ADMIN_PASSWORD` |
| Keycloak administrator | `master` | admin console <http://localhost:8080/admin> | `admin` (`KC_BOOTSTRAP_ADMIN_USERNAME`) | `KC_BOOTSTRAP_ADMIN_PASSWORD` |

The administrator cannot sign in on the web app's login page, and `alice`/`bob` cannot sign in to the admin console.
If a login page stops working, start again from the web app: the long `login-actions/...execution=...` URL expires.

| Step | URL / action | What you see |
|---|---|---|
| 1 | <http://localhost:8081> | Landing page with the demo accounts |
| 2 | **Sign in with Keycloak** | Themed Keycloak login page (registration, "forgot password", language switcher) |
| 3 | Log in as `alice` | Profile: realm role `app-user`, group `employees`, token claims |
| 4 | Press **Read reports** | `HTTP 200` - allowed by policy `employee-policy` |
| 5 | Press **Write report** or **Admin panel** | `HTTP 403` - Keycloak denies, alice is not `app-admin` |
| 6 | **Sign out**, log in as `bob` | Roles `app-admin` + `app-user`, group `managers`; all four calls return 200/201 |
| 7 | <http://localhost:8080/admin> (admin user from `.env`) | Realm `demo` > Clients > `demo-api` > Authorization: resources, scopes, policies, permissions |
| 8 | Wrong password five times | Account temporarily locked (brute-force protection) |
| 9 | Realm `demo` > Events | Login events and admin events are recorded |

## 4. Verify automatically

```bash
scripts/verify.sh
```

Runs 23 checks: OIDC discovery and JWKS, PKCE redirect, API rejects missing/invalid tokens, the authorization
matrix for alice and bob (RBAC), and the service-to-service flow (client credentials, allowed and denied resources). Expected last line: `VERIFY OK` (exit code 0).

Manual equivalent with curl (needs `DEMO_CLI_ENABLED=true`):

```bash
set -a; . ./.env; set +a
TOKEN=$(curl -s -d grant_type=password -d client_id=demo-cli -d username=alice \
  --data-urlencode "password=$DEMO_USER_PASSWORD" \
  "$KC_HOSTNAME/realms/$DEMO_REALM/protocol/openid-connect/token" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/reports   # 200
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8082/api/admin     # 403
curl -i http://localhost:8082/api/reports                                     # 401
```

## 5. Run the unit tests

No containers needed:

```bash
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt   # or: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q                           # 78 tests
```

## 6. Day-to-day commands

| Task | Command |
|---|---|
| Logs | `podman compose logs -f keycloak` (or `docker compose ...`) |
| Stop, keep data | `scripts/stop.sh` |
| Stop and delete database | `scripts/stop.sh --volumes` |
| Re-import the realm after editing `demo-realm.json` | `scripts/stop.sh --volumes && scripts/start.sh` |
| Remove venv, caches, stack | `scripts/cleanup.sh` |
| Remove pulled and built images | `scripts/cleanup-images.sh` |
| Call the API as a backend service | `set -a; . ./.env; set +a; .venv/bin/python service/service_client.py` |
| Run the apps without containers (needs Keycloak running) | see [Docs/Configuration.md](Configuration.md#running-the-apps-without-containers) |

## 7. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Cannot connect to Podman` | `podman machine start` |
| Port already in use | Change `KEYCLOAK_PORT`/`WEBAPP_PORT`/`API_PORT` **and** the matching `KC_HOSTNAME`/`WEBAPP_PUBLIC_URL`/`API_PUBLIC_URL` in `.env`, then `scripts/stop.sh --volumes && scripts/start.sh` |
| "Invalid username or password" for `admin` on the web app login | Wrong place: `admin` exists only in the `master` realm, use <http://localhost:8080/admin> |
| Login: "Invalid parameter: redirect_uri" | `WEBAPP_PUBLIC_URL` changed after the realm was imported - re-import (`stop.sh --volumes`) or edit the client in the admin console |
| `verify.sh`: cannot obtain tokens | `.env` passwords differ from those imported (regenerated `.env` without wiping the DB), or `DEMO_CLI_ENABLED=false` |
| API returns 401 with a valid token | Issuer mismatch: tokens must be obtained through `KC_HOSTNAME`, the API validates `iss` against it |
| API returns 503 | Keycloak unreachable from the API container: `compose logs api keycloak` |
| Edited the theme and see no change | Rebuild: `scripts/start.sh` (the theme is baked into the image) |
