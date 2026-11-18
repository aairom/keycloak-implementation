"""Log dashboard: an OpenID Connect client for Keycloak that records and displays what happens around it.

What is logged (all into the ``logapp`` schema, see ``store.py``):
  * auth events of this app        LOGIN, LOGIN_FAILED, LOGOUT, ACCESS_DENIED
  * token lifecycle                TOKEN_EXPIRY_WARNING, TOKEN_REFRESH, TOKEN_REFRESH_FAILED, TOKEN_EXPIRED
  * HTTP access of this app        HTTP_REQUEST (method, path, status, duration)
  * calls to the demo API          API_CALL (with the user's token)
  * service-to-service calls       S2S_REQUEST / S2S_ERROR (client credentials of ``demo-service``)
  * Keycloak's own event log       LOGIN, LOGIN_ERROR, LOGOUT, REFRESH_TOKEN, CLIENT_LOGIN ... (see event_sync.py)

Tokens never reach the browser or the database: they live in an in-process vault keyed by an opaque session id,
so the app runs with ONE gunicorn worker (threads) and users sign in again after a restart.
"""
from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from functools import wraps

import requests
from authlib.integrations.flask_client import OAuth
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request, session,
                   url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

from event_sync import KeycloakEventSync
from log_config import Config
from log_helpers import (DAY_MS, build_logout_url, decode_jwt_payload, fmt_day, fmt_ts, page_count,
                         page_number, parse_filters, realm_roles, seconds_left, severity)
from store import Store
from token_source import TokenSource

log = logging.getLogger("logapp")

API_CALLS = {  # key -> (method, path, label)
    "me": ("GET", "/api/me", "Who am I?"),
    "reports": ("GET", "/api/reports", "Read reports (app-user)"),
    "admin": ("GET", "/api/admin", "Admin panel (app-admin)"),
}
ADMIN_API_SCOPE = "kc-admin-api"  # Keycloak 26.8+: adds the Admin REST API audience to the token
RANGES = {"1d": 1, "7d": 7, "30d": 30}
NO_LIFECYCLE = {"static", "healthz", "login", "callback", "logout"}
EVENT_KINDS = ("auth", "access", "token", "api", "s2s")


class TokenVault:
    """Server-side token storage keyed by session id (never serialised, never sent to the browser)."""

    def __init__(self):
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def put(self, sid: str, entry: dict) -> None:
        with self._lock:
            self._data[sid] = entry

    def get(self, sid: str | None) -> dict | None:
        with self._lock:
            return self._data.get(sid) if sid else None

    def pop(self, sid: str | None) -> dict | None:
        with self._lock:
            return self._data.pop(sid, None) if sid else None


def create_app(config: Config, store: Store, oauth: OAuth | None = None, http=requests,
               s2s_tokens: TokenSource | None = None, sync: KeycloakEventSync | None = None,
               clock=time.time) -> Flask:
    """Application factory; ``oauth``, ``http``, ``s2s_tokens``, ``sync`` and ``clock`` can be injected in tests."""
    app = Flask(__name__)
    app.config.update(SECRET_KEY=config.session_secret, SESSION_COOKIE_NAME="logapp_session",
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_SECURE=config.secure_cookies)
    if config.trust_proxy:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    if oauth is None:
        oauth = OAuth(app)
        oauth.register(name="keycloak", client_id=config.client_id, client_secret=config.client_secret,
                       server_metadata_url=config.discovery_url,
                       client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"})
    kc = oauth.keycloak
    vault = TokenVault()
    s2s = s2s_tokens or TokenSource(config.token_url, config.service_client_id, config.service_client_secret, http)
    app.extensions["logapp"] = {"store": store, "vault": vault, "sync": sync, "s2s": s2s}

    def now_ms() -> int:
        return int(clock() * 1000)

    def record(event_type: str, kind: str, **fields) -> None:
        """Store an event; logging must never break a request."""
        try:
            store.add_event(event_type=event_type, kind=kind, ts=now_ms(), **fields)
        except Exception:
            log.exception("could not store event %s", event_type)

    def elapsed_ms(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)

    def is_admin() -> bool:
        return config.admin_role in session.get("roles", [])

    # ---- token lifecycle ------------------------------------------------------------------------------
    def refresh_tokens(sid: str, entry: dict, reason: str) -> bool:
        started = time.perf_counter()
        who = dict(username=session.get("user"), session_id=session.get("ksid"))
        try:
            if not entry.get("refresh_token"):
                raise RuntimeError("no refresh token")
            resp = http.post(kc.load_server_metadata()["token_endpoint"], timeout=10,
                             data={"grant_type": "refresh_token", "refresh_token": entry["refresh_token"],
                                   "client_id": config.client_id, "client_secret": config.client_secret})
            resp.raise_for_status()
            tok = resp.json()
            new_claims = decode_jwt_payload(tok["access_token"])
        except Exception as exc:
            record("TOKEN_REFRESH_FAILED", "token", error=str(exc)[:200], duration_ms=elapsed_ms(started),
                   detail={"reason": reason}, **who)
            return False
        entry.update(access_token=tok["access_token"], id_token=tok.get("id_token", entry.get("id_token")),
                     refresh_token=tok.get("refresh_token", entry["refresh_token"]))
        exp = new_claims.get("exp")
        store.touch_session(sid, now_ms(), access_expires_at=int(exp * 1000) if exp else None, refreshed=True)
        record("TOKEN_REFRESH", "token", duration_ms=elapsed_ms(started),
               detail={"reason": reason, "expires_in": seconds_left(exp, clock())}, **who)
        return True

    def end_local_session(sid: str | None, reason: str) -> None:
        vault.pop(sid)
        if sid:
            store.end_session(sid, now_ms(), reason)
        session.clear()

    def enforce_token_lifecycle(sid: str):
        """Warn before the access token expires, refresh it, and end the session when that is impossible."""
        entry = vault.get(sid)
        if entry is None:  # process restarted: the server-side tokens are gone
            end_local_session(sid, "server_restart")
            return None
        store.touch_session(sid, now_ms())
        exp = decode_jwt_payload(entry["access_token"]).get("exp")
        left = seconds_left(exp, clock())
        if left > config.expiry_warn:
            return None
        if entry.get("warned_exp") != exp:  # one warning per access token
            entry["warned_exp"] = exp
            record("TOKEN_EXPIRY_WARNING", "token", username=session.get("user"), session_id=session.get("ksid"),
                   detail={"seconds_left": left})
        if refresh_tokens(sid, entry, "auto") or left > 0:
            return None
        record("TOKEN_EXPIRED", "token", username=session.get("user"), session_id=session.get("ksid"))
        end_local_session(sid, "token_expired")
        flash("Your session expired. Please sign in again.", "error")
        return redirect(url_for("index"))

    # ---- request hooks: access log ----------------------------------------------------------------------
    @app.before_request
    def begin():
        g.started = time.perf_counter()
        sid = session.get("sid")
        if sid and request.endpoint not in NO_LIFECYCLE:
            return enforce_token_lifecycle(sid)
        return None

    @app.after_request
    def access_log(resp):
        if request.endpoint not in ("static", "healthz"):
            record("HTTP_REQUEST", "access", username=session.get("user"), session_id=session.get("ksid"),
                   method=request.method, path=request.path, status=resp.status_code,
                   duration_ms=elapsed_ms(g.get("started", time.perf_counter())), ip=request.remote_addr)
        return resp

    @app.context_processor
    def inject():
        return {"user": session.get("user"), "admin": is_admin(), "csrf": session.get("csrf"),
                "client_id": config.client_id}

    app.jinja_env.filters.update(ts=fmt_ts, day=fmt_day)
    app.jinja_env.globals["severity"] = severity

    # ---- access control ---------------------------------------------------------------------------------
    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("sid"):
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def admin_required(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if not is_admin():
                store.audit(session.get("user"), f"{request.method} {request.path}", "denied", ip=request.remote_addr,
                            now=now_ms())
                record("ACCESS_DENIED", "auth", username=session.get("user"), session_id=session.get("ksid"),
                       path=request.path, error=f"requires realm role {config.admin_role}")
                abort(403, f"This page needs the realm role {config.admin_role}.")
            return fn(*args, **kwargs)
        return wrapper

    def check_csrf():
        if request.form.get("csrf") != session.get("csrf"):
            abort(400, "invalid CSRF token")

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    def http_error(exc):
        return render_template("error.html", code=exc.code, message=exc.description), exc.code

    # ---- authentication routes --------------------------------------------------------------------------
    @app.get("/")
    def index():
        if session.get("sid"):
            return redirect(url_for("dashboard"))
        return render_template("index.html")

    @app.get("/login")
    def login():
        return kc.authorize_redirect(f"{config.public_url}/callback")

    @app.get("/callback")
    def callback():
        try:
            token = kc.authorize_access_token()
        except Exception as exc:  # state mismatch, denied consent, bad code ...
            log.warning("login failed: %s", exc)
            record("LOGIN_FAILED", "auth", error=str(exc)[:200], ip=request.remote_addr)
            flash("Login failed. Please try again.", "error")
            return redirect(url_for("index"))
        claims = token.get("userinfo") or {}
        access = decode_jwt_payload(token["access_token"])
        username = claims.get("preferred_username") or access.get("preferred_username") or claims.get("sub")
        roles = realm_roles(access)
        ksid = access.get("sid") or access.get("session_state")
        if session.get("sid"):
            end_local_session(session["sid"], "replaced")
        sid = secrets.token_urlsafe(24)
        session.clear()
        vault.put(sid, {"access_token": token["access_token"], "id_token": token.get("id_token"),
                        "refresh_token": token.get("refresh_token")})
        session.update(sid=sid, user=username, name=claims.get("name") or username, roles=roles, ksid=ksid,
                       csrf=secrets.token_urlsafe(16))
        exp = access.get("exp")
        store.start_session(sid, username=username, user_id=claims.get("sub"), kc_session_id=ksid, roles=roles,
                            ip=request.remote_addr, access_expires_at=int(exp * 1000) if exp else None,
                            now=now_ms())
        record("LOGIN", "auth", username=username, user_id=claims.get("sub"), session_id=ksid,
               client_id=config.client_id, ip=request.remote_addr, detail={"roles": roles})
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        sid, ksid, name = session.get("sid"), session.get("ksid"), session.get("user")
        entry = vault.get(sid) or {}
        id_token = entry.get("id_token")
        if sid:
            record("LOGOUT", "auth", username=name, session_id=ksid, client_id=config.client_id,
                   ip=request.remote_addr)
            end_local_session(sid, "logout")
        try:
            end_session = kc.load_server_metadata()["end_session_endpoint"]
        except Exception:  # identity provider unreachable: still logged out locally
            return redirect(url_for("index"))
        return redirect(build_logout_url(end_session, id_token, f"{config.public_url}/", config.client_id))

    @app.get("/healthz")
    def healthz():
        ok = store.ping()
        return jsonify(status="UP" if ok else "DOWN", database=ok), (200 if ok else 503)

    # ---- dashboard --------------------------------------------------------------------------------------
    def current_filters() -> dict:
        """Admins may filter freely; everybody else is pinned to their own username."""
        return parse_filters(request.args, force_username=None if is_admin() else session.get("user"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        filters = current_filters()
        page = page_number(request.args)
        rows, total = store.query_events(filters, page, config.page_size)
        entry = vault.get(session["sid"]) or {}
        exp = decode_jwt_payload(entry.get("access_token", "")).get("exp")
        form = {k: request.args.get(k, "") for k in ("username", "event_type", "kind", "source", "status", "q",
                                                      "date_from", "date_to")}
        return render_template("dashboard.html", rows=rows, total=total, page=page,
                               pages=page_count(total, config.page_size), form=form,
                               event_types=store.event_types(), kinds=EVENT_KINDS,
                               live=request.args.get("live") == "1", api_calls=API_CALLS,
                               expires_in=seconds_left(exp, clock()), api_result=session.pop("api_result", None),
                               sync_error=(sync.last_error if sync else None),
                               args={k: v for k, v in request.args.items() if k != "page"})

    @app.get("/events.json")
    @login_required
    def events_json():
        """Same filters as the dashboard, as JSON (polling clients, scripts/verify.sh)."""
        rows, total = store.query_events(current_filters(), page_number(request.args), config.page_size)
        return jsonify(total=total, page=page_number(request.args), page_size=config.page_size, events=rows)

    @app.post("/api-call/<key>")
    @login_required
    def api_call(key):
        check_csrf()
        if key not in API_CALLS:
            abort(404)
        method, path, label = API_CALLS[key]
        entry = vault.get(session["sid"]) or {}
        started, status, body = time.perf_counter(), 0, {}
        try:
            resp = http.request(method, config.api_base_url + path, timeout=10,
                                headers={"Authorization": f"Bearer {entry.get('access_token', '')}"})
            status = resp.status_code
            try:
                body = resp.json()
            except ValueError:
                body = {"raw": resp.text[:300]}
        except requests.RequestException as exc:
            body = {"error": f"API unreachable: {exc}"}
        record("API_CALL", "api", username=session.get("user"), session_id=session.get("ksid"), method=method,
               path=path, status=status or None, duration_ms=elapsed_ms(started), client_id="demo-api",
               error=None if 0 < status < 400 else body.get("message") or body.get("error"))
        session["api_result"] = {"label": label, "request": f"{method} {path}", "status": status, "body": body}
        return redirect(url_for("dashboard"))

    @app.post("/s2s")
    @login_required
    def s2s_call():
        """Service-to-service probe: this app acts as ``demo-service`` (client credentials) towards the API."""
        check_csrf()
        path, started, status, body, error = "/api/service/data", time.perf_counter(), 0, {}, None
        try:
            resp = http.get(config.api_base_url + path, timeout=10,
                            headers={"Authorization": f"Bearer {s2s.token()}"})
            status = resp.status_code
            body = resp.json() if resp.content else {}
            if status == 401:
                s2s.invalidate()
            if status >= 400:
                error = body.get("message") or body.get("error")
        except (requests.RequestException, ValueError) as exc:
            error = f"{type(exc).__name__}: {exc}"[:200]
        record("S2S_REQUEST" if status and status < 400 else "S2S_ERROR", "s2s", username=f"service-account-{config.service_client_id}",
               client_id=config.service_client_id, method="GET", path=path, status=status or None,
               duration_ms=elapsed_ms(started), error=error, detail={"triggered_by": session.get("user")})
        session["api_result"] = {"label": "Service-to-service (client credentials)", "request": f"GET {path}",
                                 "status": status, "body": body or {"error": error}}
        return redirect(url_for("dashboard"))

    # ---- admin panel ------------------------------------------------------------------------------------
    @app.get("/admin")
    @admin_required
    def admin():
        range_key = request.args.get("range") if request.args.get("range") in RANGES else "7d"
        days = RANGES[range_key]
        now = now_ms()
        stats = store.stats(now - days * DAY_MS, now, config.idle_minutes * 60_000, days=max(days, 7))
        peak = max([d["logins"] + d["failed"] for d in stats["daily"]] + [1])
        store.audit(session.get("user"), "view admin panel", "ok", ip=request.remote_addr, now=now)
        return render_template("admin.html", stats=stats, range_key=range_key, ranges=list(RANGES), peak=peak,
                               sessions=store.recent_sessions(10), audit=store.recent_audit(10), sync=sync,
                               now=now)

    @app.post("/admin/sync")
    @admin_required
    def admin_sync():
        check_csrf()
        added = sync.run_safely() if sync else 0
        store.audit(session.get("user"), "sync keycloak events", "ok" if not (sync and sync.last_error) else "error",
                    target=f"{added} new", ip=request.remote_addr, now=now_ms())
        flash(f"Keycloak event sync finished: {added} new event(s)." if not (sync and sync.last_error)
              else f"Sync failed: {sync.last_error}", "error" if sync and sync.last_error else "info")
        return redirect(url_for("admin"))

    return app


def build(env=None) -> Flask:
    """Wire the production objects: config -> store -> Keycloak event sync (background thread) -> Flask app."""
    env = os.environ if env is None else env
    config = Config.from_env(env)
    store = Store(config.database_url)
    store.init_schema()
    # Event sync authenticates as the service account of the log app's own client (realm role view-events).
    sync = KeycloakEventSync(store, TokenSource(config.token_url, config.client_id, config.client_secret,
                                          scope=ADMIN_API_SCOPE),
                             config.admin_api_base, interval=config.sync_interval)
    app = create_app(config, store, sync=sync)
    sync.start()
    return app


def get_wsgi_app() -> Flask:  # gunicorn entry point: ``log_app:get_wsgi_app()``
    logging.basicConfig(level=logging.INFO)
    return build()


if __name__ == "__main__":  # local development server only
    logging.basicConfig(level=logging.INFO)
    build().run(host=os.environ.get("LOGAPP_HOST", "127.0.0.1"), port=int(os.environ.get("LOGAPP_PORT", "8083")))
