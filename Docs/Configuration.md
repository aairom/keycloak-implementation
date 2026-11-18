# Configuration reference

## Dependencies

| Component | Version (pinned) | Source | Purpose |
|---|---|---|---|
| Keycloak | 26.8.2 (`KEYCLOAK_VERSION`) | `quay.io/keycloak/keycloak` | Identity and access management |
| PostgreSQL | 17-alpine | `docker.io/library/postgres` | Keycloak database |
| Caddy | 2-alpine | `docker.io/library/caddy` | HTTPS reverse proxy (online only) |
| Python | 3.12-slim | `docker.io/library/python` | Runtime of web app and API images |
| Flask / Authlib | 3.1.3 / 1.9.8 | PyPI | Web app and OIDC client |
| PyJWT[crypto] / requests / gunicorn | 2.15.1 / 2.34.2 / 27.0.1 | PyPI | API token validation, HTTP, WSGI server |
| pytest | 9.2.0 | PyPI | Tests (development only) |

Python dependency versions were checked against OSV.dev for known vulnerabilities when this project was created.
Re-check them (`uv pip list --outdated`, OSV, `pip-audit`) before every release. Per-service pins live in
`webapp/requirements.txt` and `api/requirements.txt`; the root `requirements.txt` is the union plus pytest for development.

Host tooling: Podman or Docker with compose, `curl`, `python3`, `openssl`, `uv` (tests only).

## Environment variables (`.env`)

`scripts/init-env.sh` creates `.env` from `.env.example` and replaces every `changeme-*` value with a random one.
Never commit `.env`. Compose refuses to start when a required variable is missing.

### Keycloak and database

| Variable | Default | Description |
|---|---|---|
| `KEYCLOAK_VERSION` | `26.8.2` | Image tag used as build argument `KC_IMAGE_TAG`. Upgrade by changing it and re-running `scripts/start.sh` |
| `KC_HOSTNAME` | `http://localhost:8080` | **Public** Keycloak URL as browsers see it; becomes the token `iss`. Must be `https://...` online |
| `KEYCLOAK_PORT` | `8080` | Host port for Keycloak |
| `BIND_ADDRESS` | `127.0.0.1` | Interface for published ports. Keep `127.0.0.1` online (Caddy is the only public entry); use `0.0.0.0` to expose a LAN demo |
| `KC_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` | `admin` / random | Temporary master-realm admin, created on first start only. Create a permanent admin and delete this one for production |
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | `keycloak` / `keycloak` / random | Database credentials |

### Realm import (placeholders in `keycloak/realm/demo-realm.json`)

The realm is imported **only on first start** (`IGNORE_EXISTING`). Changing these later requires wiping the database
(`scripts/stop.sh --volumes`) or editing the realm in the admin console.

| Variable | Default | Description |
|---|---|---|
| `DEMO_REALM` | `demo` | Realm name (appears in all URLs and in the token issuer) |
| `DEMO_USER_PASSWORD` | random | Password of user `alice` (role `app-user`) |
| `DEMO_ADMIN_PASSWORD` | random | Password of user `bob` (role `app-admin`) |
| `DEMO_REGISTRATION_ALLOWED` | `true` | Self-registration link on the login page |
| `DEMO_CLI_ENABLED` | `true` | Enables client `demo-cli` (password grant) used by `verify.sh`; **set `false` in production** |
| `WEBAPP_CLIENT_SECRET` | random | Secret of confidential client `demo-webapp` |
| `API_CLIENT_SECRET` | random | Secret of resource server client `demo-api` |
| `SERVICE_CLIENT_SECRET` | random | Secret of client `demo-service` (client credentials grant, used by `service/service_client.py` and `verify.sh`) |

### Applications

| Variable | Default | Description |
|---|---|---|
| `WEBAPP_PUBLIC_URL` | `http://localhost:8081` | Public URL of the web app; registered as redirect URI `<url>/callback`, web origin and post-logout URI |
| `WEBAPP_PORT` / `API_PORT` | `8081` / `8082` | Host ports |
| `API_PUBLIC_URL` | `http://localhost:8082` | Public API URL (used by `verify.sh`) |
| `WEBAPP_SESSION_SECRET` | random | Signs the Flask session cookie. Rotating it logs everybody out |

Variables set by compose inside the containers (not in `.env`):

| Service | Variable | Value | Meaning |
|---|---|---|---|
| web app | `OIDC_DISCOVERY_URL` | `http://keycloak:8080/realms/<realm>/.well-known/openid-configuration` | Back-channel discovery |
| web app | `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | `demo-webapp` / `WEBAPP_CLIENT_SECRET` | Client credentials |
| web app | `API_BASE_URL` | `http://api:8082` | Internal API address |
| API | `OIDC_ISSUER` | `${KC_HOSTNAME}/realms/<realm>` | Expected `iss` claim |
| API | `API_AUDIENCE` | `demo-api` | Expected `aud` claim |
| Keycloak | `KC_HOSTNAME_BACKCHANNEL_DYNAMIC` | `true` | Containers reach Keycloak by service name while tokens keep the public issuer |
| Keycloak | `KC_PROXY_HEADERS` | `xforwarded` (prod overlay) | Trust Caddy's `X-Forwarded-*` headers |

### Online deployment (`docker-compose.prod.yml`)

| Variable | Description |
|---|---|
| `KC_PUBLIC_HOST`, `APP_PUBLIC_HOST`, `API_PUBLIC_HOST` | DNS names (no scheme) served by Caddy; each gets a Let's Encrypt certificate |
| `ACME_EMAIL` | Contact e-mail for Let's Encrypt |
| `ADMIN_ALLOWED_CIDR` | Quoted, space-separated CIDRs allowed to reach `/admin*` and `/realms/master*` (default: everyone) |

### Script variables

`COMPOSE_CMD` (force `docker compose`), `START_TIMEOUT` (default 300 s), `STOP_TIMEOUT` (default 30 s),
`PROJECT_IMAGES` (images deleted by `cleanup-images.sh`).

## Realm model (`keycloak/realm/demo-realm.json`)

| Element | Definition |
|---|---|
| Realm roles | `app-user`; `app-admin` (composite, includes `app-user`); `app-service` (machine identity) |
| Groups | `employees` (-> `app-user`, default group for new users), `managers` (-> `app-admin`) |
| Users | `alice` (employees), `bob` (managers) - e-mail verified, non-temporary passwords from `.env` |
| Client `demo-webapp` | Confidential, authorization code + PKCE S256, exact redirect URI, no implicit/password grants; mappers: audience `demo-api`, `groups` |
| Client `demo-api` | Resource server with Authorization Services, `ENFORCING`, decision strategy `UNANIMOUS` |
| Client `demo-service` | Confidential, **client credentials only** (no browser flows); its service account has realm role `app-service`; audience mapper `demo-api` |
| Client `demo-cli` | Public, password grant, for scripts only |
| Resources / scopes | `reports` (`read`, `write`), `admin-panel` (`access`), `service-data` (`read`) |
| Policies | role policies `employee-policy` (`app-user`), `manager-policy` (`app-admin`), `service-policy` (`app-service`) |
| Permissions | `reports#read` <- employee, `reports#write` <- manager, `admin-panel#access` <- manager, `service-data#read` <- service |
| Security | Brute-force protection (5 failures, lock grows by 60 s up to 15 min), password policy `length(8) and notUsername`, access token 5 min, SSO idle 30 min / max 10 h |
| Operations | Login and admin events enabled, languages en/fr/de/es, login theme `demo` |

Because `app-admin` includes `app-user`, bob satisfies `employee-policy` too. The service account holds only
`app-service`, so it can read `/api/service/data` but gets 403 on reports and the admin panel; users alice and bob
get 403 on `/api/service/data`.

### API endpoints

| Method and path | Permission checked in Keycloak | Allowed identities |
|---|---|---|
| `GET /api/health` | none (public) | anyone |
| `GET /api/me` | valid token only | any authenticated user or service |
| `GET /api/reports` | `reports#read` | alice, bob |
| `POST /api/reports` | `reports#write` | bob |
| `GET /api/admin` | `admin-panel#access` | bob |
| `GET /api/service/data` | `service-data#read` | `demo-service` |

### Service-to-service client

```bash
set -a; . ./.env; set +a
.venv/bin/python service/service_client.py      # prints HTTP 200 and the JSON payload
```

`service/service_client.py` reads `KC_HOSTNAME`, `DEMO_REALM`, `SERVICE_CLIENT_SECRET`, `API_PUBLIC_URL` (and optionally
`SERVICE_CLIENT_ID`, default `demo-service`), requests a token with `grant_type=client_credentials`, caches it until
30 seconds before expiry and calls the API. Import `ServiceClient` to reuse it in your own backend jobs.

## Customization

| Goal | How |
|---|---|
| Add a user, role, client | Edit `demo-realm.json` and re-import, **or** configure it in the admin console and copy the result back with Realm settings > Action > Partial export (includes clients and groups/roles; secrets are masked, so keep them as `${PLACEHOLDERS}`) |
| Add a protected endpoint | Add a resource/scope/permission in the realm (admin console > Clients > `demo-api` > Authorization), then decorate the route with `@require_permission("<resource>", "<scope>")` in `api/api_app.py` |
| Another service identity | Copy the `demo-service` client and its `service-account-*` user in `demo-realm.json` (new `clientId`, secret placeholder, `serviceAccountClientId`), give the service account the realm role(s) it needs, and pass its secret to Keycloak through compose |
| Another client application | Create a client (admin console), reuse `TokenValidator` for APIs or the Authlib setup in `webapp/app.py` for web apps; any OIDC library works with `KC_HOSTNAME/realms/<realm>/.well-known/openid-configuration` |
| Branding | Edit `keycloak/themes/demo/login/resources/css/demo.css` (add `login.ftl` overrides for markup changes), then rebuild with `scripts/start.sh` |
| Identity brokering / social login / LDAP | Admin console > Identity providers / User federation (not pre-configured) |
| Enable MFA | Admin console > Authentication > Required actions: enable "Configure OTP" and make it a default action |
| E-mail (verification, password reset) | Admin console > Realm settings > Email (SMTP). `verifyEmail` is off in the demo because no SMTP server is configured |
| Newer Keycloak | Set `KEYCLOAK_VERSION` and re-run `scripts/start.sh`. Read the upstream upgrade guide; the theme parent (`keycloak.v2`) may change between major versions |
| Scale out | Run several Keycloak replicas behind the proxy; Keycloak clusters over the shared database (see the upstream "High availability" guide) |

## Running the apps without containers

With the Keycloak stack running (`scripts/start.sh`), the web app and API can run from the virtualenv for development:

```bash
set -a; . ./.env; set +a
export OIDC_DISCOVERY_URL="$KC_HOSTNAME/realms/$DEMO_REALM/.well-known/openid-configuration"
export OIDC_ISSUER="$KC_HOSTNAME/realms/$DEMO_REALM" API_AUDIENCE=demo-api
.venv/bin/python api/api_app.py &                                    # http://127.0.0.1:8082
OIDC_CLIENT_ID=demo-webapp OIDC_CLIENT_SECRET="$WEBAPP_CLIENT_SECRET" API_BASE_URL=http://127.0.0.1:8082 \
  .venv/bin/python webapp/app.py                                     # http://127.0.0.1:8081
```

Stop the containerised `webapp` and `api` first (`podman compose stop webapp api`) so the ports are free.
Use `localhost`, not `127.0.0.1`, in the browser: the redirect URI is `http://localhost:8081/callback`.

## Extending the test application

| Task | Steps |
|---|---|
| New protected endpoint | 1) Admin console > `demo-api` > Authorization: add a resource, scopes, a policy and a permission, mirror them in `demo-realm.json`. 2) In `api/api_app.py` add a route decorated with `@require_permission("<resource>", "<scope>")`. 3) Add the case to `tests/test_api_app.py` (the fake policy point has a role-to-permission table) and to `scripts/verify.sh`. |
| New role for users | Add the role and a group (or user) mapping in `demo-realm.json`; add a role policy and attach it to a permission. Roles appear in the token as `realm_access.roles` |
| New button in the web app | Add an entry to `API_CALLS` in `webapp/app.py`; the profile page renders it automatically |
| Different identity provider claims | Add a protocol mapper to the client in `demo-realm.json` (see `groups` on `demo-webapp`) |
| Checks | `.venv/bin/python -m pytest -q` (no containers), then `scripts/verify.sh` against the running stack |
