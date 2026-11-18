# Architecture

## Components

```mermaid
flowchart TB
    subgraph Client["Browser"]
        B([User])
    end
    subgraph Stack["Compose project keycloak-demo"]
        direction TB
        W["webapp (Flask + Authlib)<br/>confidential OIDC client demo-webapp<br/>:8081"]
        A["api (Flask + PyJWT)<br/>resource server demo-api<br/>:8082"]
        K["keycloak 26.8.2 (optimized build)<br/>realm demo, theme demo<br/>:8080 / management :9000"]
        L["logapp (Flask + Authlib)<br/>OIDC client demo-logapp<br/>log dashboard :8083"]
        P[("postgres 17<br/>volume postgres-data<br/>schemas public + logapp")]
        C{{"caddy (prod overlay)<br/>HTTPS + headers + admin allow-list<br/>:80 / :443"}}
    end
    B -->|browser| C
    C -->|"auth host"| K
    C -->|"app host"| W
    C -->|"api host"| A
    B -.->|"local mode: direct"| K
    B -.->|"local mode: direct"| W
    W -->|"discovery, token (back channel)"| K
    W -->|"Bearer token"| A
    A -->|"JWKS, UMA decision"| K
    K -->|JDBC| P
    B -->|"dashboard"| L
    L -->|"login, refresh, admin REST view-events"| K
    L -->|"s2s Bearer"| A
    L -->|"events, sessions, audit"| P
    C -->|"logs host"| L
```

| Component | Technology | Responsibility | State |
|---|---|---|---|
| `keycloak` | Official image, built with `kc.sh build` (`KC_DB=postgres`, health and metrics on) | Authentication, SSO sessions, token issuing, authorization policies, admin console, events | PostgreSQL |
| `postgres` | PostgreSQL 17 | Persists realms, users, sessions, events | Named volume |
| `webapp` | Flask 3, Authlib, gunicorn | Browser-facing OIDC client; logs users in, shows claims, calls the API with the user's token | Stateless (signed cookie) |
| `api` | Flask 3, PyJWT, gunicorn | OAuth 2.0 resource server; validates tokens locally and asks Keycloak for permission decisions | Stateless |
| `logapp` | Flask 3, Authlib, psycopg 3, gunicorn (1 worker, 8 threads) | OIDC client that records auth, API, token and service-to-service events, pulls Keycloak's event log, serves the filterable dashboard and the admin statistics | PostgreSQL schema `logapp` (tokens only in process memory) |
| `caddy` (online only) | Caddy 2 | TLS termination with automatic certificates, security headers, admin allow-list | Volumes `caddy-data`, `caddy-config` |

## Authentication flow (OIDC authorization code + PKCE)

```mermaid
sequenceDiagram
    actor U as Browser
    participant W as webapp
    participant K as Keycloak
    U->>W: GET /login
    W->>W: generate state, nonce, code_verifier
    W-->>U: 302 /auth?code_challenge=S256(verifier)&state
    U->>K: GET /auth (front channel)
    K-->>U: login form (theme demo)
    U->>K: POST credentials
    K->>K: policies: brute-force, password, required actions
    K-->>U: 302 /callback?code&state
    U->>W: GET /callback
    W->>K: POST /token (code, code_verifier, client_secret) [back channel]
    K-->>W: access, ID and refresh tokens
    W->>W: validate ID token (nonce, issuer, signature), start session
    W-->>U: 302 /profile + session cookie (HttpOnly, SameSite=Lax, Secure online)
```

Logout is RP-initiated: `/logout` clears the local session and redirects to Keycloak's `end_session_endpoint`
with `id_token_hint`, ending the SSO session; Keycloak returns to `WEBAPP_PUBLIC_URL/`.

## Authorization model

Two layers cooperate:

1. **Identity roles and groups** - `employees` grants realm role `app-user`; `managers` grants `app-admin`
   (composite, includes `app-user`). They appear in the token as `realm_access.roles` and `groups`.
2. **Keycloak Authorization Services** on client `demo-api` - the API never hard-codes who may do what.
   It asks Keycloak for a decision on `resource#scope`; Keycloak evaluates the policies in the realm.

```mermaid
flowchart LR
    subgraph Users
        alice[alice<br/>employees]
        bob[bob<br/>managers]
    end
    alice --> ruser[role app-user]
    bob --> radmin[role app-admin]
    radmin -->|composite| ruser
    ruser --> pe[employee-policy]
    radmin --> pm[manager-policy]
    pe --> p1[permission<br/>reports#read]
    pm --> p2[permission<br/>reports#write]
    pm --> p3[permission<br/>admin-panel#access]
    p1 --> r1((reports))
    p2 --> r1
    p3 --> r2((admin-panel))
```

Request path for `GET /api/reports`:

```mermaid
flowchart TD
    R[Request with Authorization: Bearer token] --> H{Header present<br/>and well formed?}
    H -- no --> E401[401 + WWW-Authenticate]
    H -- yes --> V{Signature RS256 via JWKS,<br/>iss, aud=demo-api,<br/>exp/iat/sub valid?}
    V -- no --> E401
    V -- yes --> D["POST token endpoint<br/>grant_type=uma-ticket<br/>permission=reports#read<br/>response_mode=decision"]
    D --> X{Keycloak result}
    X -- true --> OK[200 handler runs]
    X -- "false / 403" --> E403[403 forbidden]
    D -. Keycloak unreachable .-> E503[503 upstream_unavailable]
```

## Service-to-service flow (client credentials)

```mermaid
sequenceDiagram
    participant S as service client (demo-service)
    participant K as Keycloak
    participant A as api
    S->>K: POST /token grant_type=client_credentials, client_id, client_secret
    K-->>S: access token (sub = service account, role app-service, aud demo-api)
    S->>A: GET /api/service/data (Bearer token)
    A->>A: verify signature, issuer, audience, expiry
    A->>K: UMA decision service-data#read
    K-->>A: true (service-policy)
    A-->>S: 200
```

No user and no browser are involved; the same API code path and the same policy engine decide, which is why the
service account gets 403 on `/api/reports` and `/api/admin`.

## Log dashboard

```mermaid
flowchart LR
    R[request] --> BR["before_request: start timer"]
    BR --> H[route handler]
    H --> AR["after_request: HTTP_REQUEST<br/>method, path, status, duration"]
    H -->|"callback / logout / refresh"| AU["LOGIN, LOGOUT, TOKEN_REFRESH,<br/>TOKEN_EXPIRY_WARNING, ACCESS_DENIED"]
    H -->|"api-call, s2s"| AP["API_CALL, S2S_REQUEST"]
    AR --> S[("logapp.app_events")]
    AU --> S
    AP --> S
    AU --> US[("user_sessions / audit_log")]
    KE["Keycloak /admin/realms/demo/events<br/>(service account, view-events)"] -->|"sync every N s, dedupe_key"| S
    S --> D["/dashboard and /events.json<br/>filters + pagination"]
    S --> ST["/admin statistics"]
```

* **Two sources, one table.** `source=app` rows are written by the Flask hooks; `source=keycloak` rows come from the
  events REST endpoint (`LOGIN`, `LOGIN_ERROR`, `REFRESH_TOKEN`, `CODE_TO_TOKEN`, `CLIENT_LOGIN`, ...). A content hash
  (`dedupe_key`) makes re-reading overlapping windows idempotent.
* **Authorization.** Any realm user may sign in and sees only their own rows (the username filter is pinned); the realm
  role `app-admin` sees everything and the admin panel. Denied attempts are logged as `ACCESS_DENIED`.
* **Token lifecycle.** Before each request the token is checked: with fewer than `LOGAPP_EXPIRY_WARN_SECONDS` left a
  `TOKEN_EXPIRY_WARNING` is logged and the refresh token is used (`TOKEN_REFRESH`). A failed refresh is logged as
  `TOKEN_REFRESH_FAILED`; the session ends (`TOKEN_EXPIRED`) only when the access token has really expired.
* **Token handling and PostgreSQL.** Access, ID and refresh tokens are kept only in the process memory (`TokenVault`,
  keyed by an opaque session id). The browser cookie holds the session id and a few claims, and PostgreSQL never
  receives token material: `user_sessions` stores username, roles, timestamps and the end reason only.
* **Admin API access.** Keycloak 26.8 requires the audience `<host>/admin/realms/<realm>` on Admin REST tokens, supplied by
  the optional scope `kc-admin-api`. The service account holds only `view-events`.

### PostgreSQL event flow

```mermaid
sequenceDiagram
    participant U as User
    participant L as logapp
    participant K as Keycloak
    participant P as PostgreSQL
    U->>K: login, token refresh, logout
    K->>P: INSERT public.event_entity (only types in enabledEventTypes)
    U->>L: request
    L->>P: INSERT logapp.app_events (source=app)
    loop every LOGAPP_SYNC_INTERVAL seconds
        L->>K: GET /admin/realms/demo/events?dateFrom=...&first=...&max=200 (Bearer, scope kc-admin-api)
        K-->>L: JSON events
        L->>P: INSERT ... ON CONFLICT (dedupe_key) DO NOTHING (source=keycloak)
        L->>P: UPDATE sync_state keycloak_events_watermark_ms
    end
```

Keycloak does **not** store `REFRESH_TOKEN` events by default. The realm therefore lists 25 `enabledEventTypes`
explicitly (`keycloak/realm/demo-realm.json`), including `REFRESH_TOKEN`, `LOGOUT`, `CODE_TO_TOKEN` and `CLIENT_LOGIN`.
The `TOKEN_REFRESH` rows of the application and the `REFRESH_TOKEN` rows of Keycloak are two views of the same
operation and are kept apart by the `source` column.

## Network and URL design

Browsers and containers reach Keycloak by different names, which is the classic Keycloak container pitfall:

| Actor | Address used | Why |
|---|---|---|
| Browser | `KC_HOSTNAME` (`http://localhost:8080` or `https://auth.example.com`) | Public front channel; defines the token issuer |
| webapp, api, logapp (back channel) | `http://keycloak:8080` (logapp: token, refresh and `/admin/realms/<realm>/events`) | Container-to-container, no TLS round trip through the proxy |
| Token validation in the API | `OIDC_ISSUER` = `KC_HOSTNAME/realms/<realm>` | The issuer is the public one, even though keys are fetched internally |

`KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` lets Keycloak answer internal requests with endpoints derived from the
request host, while front-channel URLs and the `iss` claim stay on `KC_HOSTNAME`.

## Configuration as code

* `keycloak/realm/demo-realm.json` is baked into the image (`/opt/keycloak/data/import`) and imported with
  `--import-realm` on first start. `${PLACEHOLDER}` values are resolved from the container environment, so the
  repository contains no secrets.
* The build stage of `keycloak/Dockerfile` runs `kc.sh build` once, so the runtime starts with `--optimized`
  (faster start, fixed DB vendor, health and metrics enabled).
* The theme `keycloak/themes/demo` extends the built-in `keycloak.v2` login theme with one stylesheet.

## Security decisions

| Topic | Decision |
|---|---|
| Browser client | Confidential client, code flow + PKCE S256, exact redirect URI, implicit and password grants off |
| Service client | Client credentials only, least-privilege role `app-service`, secret from `.env`, token cached in memory |
| Tokens | Access token 5 min. `webapp`: tokens are inside the signed (not encrypted) HttpOnly Flask cookie, never in browser storage. `logapp`: tokens only in server memory, the cookie holds an opaque session id |
| CSRF | State/nonce on login; per-session CSRF token on every POST to the API proxy route; SameSite=Lax cookies |
| API | Signature + issuer + audience + required claims; algorithm allow-list rejects `none`; authorization delegated to Keycloak policies; fail closed (deny on error) |
| Audience | Audience mapper adds `demo-api` so a token minted for another API is not accepted |
| Credentials | Brute-force detection, password policy, passwords and secrets only via `.env` (random, mode 600, git-ignored) |
| Containers | Non-root users, multi-stage builds, pinned tags, ports bound to `127.0.0.1`, management port 9000 not published |
| Transport | Online: Caddy terminates TLS, HSTS, `nosniff`, referrer policy, optional admin allow-list |
| Log dashboard data | Usernames and IP addresses are stored in `logapp`; non-admins see only their own rows (filter pinned server-side); the sync account holds `view-events` only; retention is the operator's job (see [Deployment](Deployment.md#hardening-checklist)) |
| Known demo trade-offs | Self-registration, `demo-cli` password grant and fixed demo users exist for convenience; each can be switched off (see [Deployment hardening](Deployment.md#hardening-checklist)) |

## Testing strategy

| Level | Tooling | Scope |
|---|---|---|
| Unit | pytest (213 tests) | Log dashboard (store, event sync, token lifecycle, filters, access control, verification script), token validation (expiry, issuer, audience, forged and `alg=none` tokens), policy client, API endpoints with a fake policy point, web app flows with a stubbed Authlib client, service client token caching, helpers |
| Configuration | pytest | Realm file consistency (policy/resource/scope references), no clear-text secrets, every compose variable documented, every realm placeholder passed to Keycloak, Dockerfile policy |
| End to end | `scripts/verify.sh` | Runs against the live stack, local or online: discovery, JWKS, PKCE, 401/403/200/201 matrix with real user and service tokens, then `verify_logapp.py` (scripted browser session on the dashboard) |
