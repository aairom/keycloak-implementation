# Quickstart (local)

Goal: a working Keycloak with a login-protected web app, API and log dashboard in about three minutes of attended time
(plus the image build on first run).

## 1. Prerequisites

| Tool | Version | Check |
|---|---|---|
| Podman **or** Docker, with the compose plugin | Podman 5+/Docker 24+ | `podman compose version` or `docker compose version` |
| curl, python3, openssl | any recent | used by the helper scripts |
| Free ports | 8080 (Keycloak), 8081 (web app), 8082 (API), 8083 (log dashboard) | `lsof -i :8080 -i :8081 -i :8082 -i :8083` |

macOS with Podman: start the VM first (`podman machine start`). Port 5000 is never used (AirDrop).
The scripts pick Podman first and fall back to Docker; force one with `COMPOSE_CMD="docker compose" scripts/start.sh`.

## 2. Start

```bash
git clone <this repository> keycloak-implementation && cd keycloak-implementation
scripts/start.sh
```

On the first run the script:

1. creates `.env` from `.env.example` with random secrets (`scripts/init-env.sh`),
2. builds four images (Keycloak with theme and realm, API, web app, log dashboard) and pulls PostgreSQL,
3. waits until Keycloak, the web app and the log dashboard answer, then prints the URLs.

Expect 1-3 minutes on first start (image pulls and Keycloak build step); later starts take under a minute.
The Keycloak realm `demo` is imported automatically on first start only.

## 3. Take the tour

Show your passwords: `grep -E 'DEMO_(USER|ADMIN)_PASSWORD|KC_BOOTSTRAP' .env`. There are two separate kinds of account:

| Account | Realm | Sign in at | Username | Password in `.env` |
|---|---|---|---|---|
| Demo user (employee) | `demo` | web app <http://localhost:8081> | `alice` | `DEMO_USER_PASSWORD` |
| Demo user (manager, **not** a Keycloak admin) | `demo` | web app <http://localhost:8081> | `bob` | `DEMO_ADMIN_PASSWORD` |
| Demo user (employee or manager) on the log dashboard | `demo` | log dashboard <http://localhost:8083> | `alice` / `bob` | same passwords as above |
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
| 10 | <http://localhost:8083> > **Sign in** (alice, then bob) | Log dashboard: your own events as `alice`, everybody's as `bob` |
| 11 | Dashboard buttons **Who am I?**, **Read reports (app-user)**, **Admin panel (app-admin)** and **Service-to-service call** | `API_CALL` and `S2S_REQUEST` rows with method, path, status and duration |
| 12 | Filters **User** (admins only), **Event type**, **Category**, **Origin**, **Status** (`403`, `4xx`), **From**, **To**, **Search**, **Live (5 s)**, then **Apply** or **Reset** | The table is paginated and the count in the heading updates; `/events.json` accepts the same query parameters |
| 13 | As `bob`: **Admin** (range links 1d, 7d, 30d) | Logins (Keycloak), Failed attempts, Active sessions, Token refreshes, Expiry warnings, API/HTTP requests, HTTP errors, Avg ms, Service-to-service; Most active users, Logins per day, Recent sessions, Admin audit log, Keycloak event sync with **Sync now** |

The log dashboard is its own OIDC client (`demo-logapp`). Every few seconds it also pulls Keycloak's event log through
a service account that only holds `view-events`, so Keycloak-side events (`LOGIN_ERROR`, `REFRESH_TOKEN`, ...) show up
next to the application's own rows (`source` = `app` or `keycloak`). To see the token warning quickly set
`LOGAPP_EXPIRY_WARN_SECONDS=290` in `.env` and run `scripts/start.sh` again (it recreates the container): the dashboard logs `TOKEN_EXPIRY_WARNING` and refreshes the token
(`TOKEN_REFRESH`) on the first request after 290 of the 300 token seconds are left; tick **Live (5 s)** so a request happens by itself. Keycloak's own `REFRESH_TOKEN` event appears a few seconds later (`source` = keycloak).

## 4. Verify automatically

```bash
scripts/verify.sh
```

Runs 44 checks (23 for the demo apps, 21 for the log dashboard through `scripts/verify_logapp.py`): OIDC discovery and JWKS, PKCE redirect, API rejects missing/invalid tokens, the authorization
matrix for alice and bob (RBAC), and the service-to-service flow (client credentials, allowed and denied resources), then a scripted browser session on the dashboard (login/logout events, API access, filters, Keycloak event sync, admin statistics, access control). Expected last line: `VERIFY OK` (exit code 0).

Not covered by `verify_logapp.py`: token refresh, expiry warning and Keycloak `REFRESH_TOKEN` events (they need a waiting time or a changed `LOGAPP_EXPIRY_WARN_SECONDS`). They are covered by unit tests in `tests/test_log_app.py` and by the manual step above. The dashboard part can be run alone: `set -a; . ./.env; set +a; .venv/bin/python scripts/verify_logapp.py` (variables: `LOGAPP_PUBLIC_URL`, `KC_HOSTNAME`, `DEMO_REALM`, `DEMO_USER_PASSWORD`, `DEMO_ADMIN_PASSWORD`, optional `VERIFY_INSECURE=1` for self-signed certificates).

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
.venv/bin/python -m pytest -q                           # 213 tests
```

## 6. Day-to-day commands

| Task | Command |
|---|---|
| Logs | `podman compose logs -f keycloak logapp` (or `docker compose ...`) |
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
| Port already in use | Change `KEYCLOAK_PORT`/`WEBAPP_PORT`/`API_PORT`/`LOGAPP_PORT` **and** the matching `KC_HOSTNAME`/`WEBAPP_PUBLIC_URL`/`API_PUBLIC_URL`/`LOGAPP_PUBLIC_URL` in `.env`, then `scripts/stop.sh --volumes && scripts/start.sh` |
| "Invalid username or password" for `admin` on the web app login | Wrong place: `admin` exists only in the `master` realm, use <http://localhost:8080/admin> |
| Login: "Invalid parameter: redirect_uri" | `WEBAPP_PUBLIC_URL` (or `LOGAPP_PUBLIC_URL` for the dashboard) changed after the realm was imported - re-import (`stop.sh --volumes`) or edit the client in the admin console |
| `verify.sh`: cannot obtain tokens | `.env` passwords differ from those imported (regenerated `.env` without wiping the DB), or `DEMO_CLI_ENABLED=false` |
| API returns 401 with a valid token | Issuer mismatch: tokens must be obtained through `KC_HOSTNAME`, the API validates `iss` against it |
| API returns 503 | Keycloak unreachable from the API container: `compose logs api keycloak` |
| Edited the theme and see no change | Rebuild: `scripts/start.sh` (the theme is baked into the image) |
| Dashboard: after a restart you are asked to sign in again | By design: tokens live in the log app's memory (one gunicorn worker); old sessions are closed with reason `server_restart` |
| Dashboard shows no `source=keycloak` rows | Sync needs the `kc-admin-api` scope and `view-events`; check the Admin page (last sync error) and `compose logs logapp` |
