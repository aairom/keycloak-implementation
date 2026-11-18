"""Unit tests for logapp/log_app.py with a stubbed Authlib client, stubbed HTTP and an in-memory SQLite store."""
import base64
import json
from types import SimpleNamespace

import pytest
import requests
from flask import redirect

from log_app import API_CALLS, create_app
from log_config import Config
from store import Store

ENV = {
    "OIDC_DISCOVERY_URL": "http://kc/realms/demo/.well-known/openid-configuration",
    "OIDC_CLIENT_ID": "demo-logapp", "OIDC_CLIENT_SECRET": "cs", "LOGAPP_SESSION_SECRET": "ss",
    "LOGAPP_PUBLIC_URL": "http://localhost:8083", "API_BASE_URL": "http://api:8082",
    "LOGAPP_DATABASE_URL": "sqlite:///:memory:", "SERVICE_CLIENT_SECRET": "svc",
}
NOW = 1_700_000_000.0


def _jwt(payload):
    return "h." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".s"


def access_token(roles, exp=NOW + 300, username="alice"):
    return _jwt({"exp": exp, "preferred_username": username, "sid": "kc-sid-1",
                 "realm_access": {"roles": roles + ["offline_access"]}})


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class FakeKeycloak:
    def __init__(self, username="alice", roles=("app-user",), exp_in=300, fail=False, metadata=True):
        self.username, self.roles, self.exp_in, self.fail, self.metadata = username, list(roles), exp_in, fail, metadata

    def authorize_redirect(self, redirect_uri):
        self.redirect_uri = redirect_uri
        return redirect("http://kc/auth?code_challenge_method=S256")

    def authorize_access_token(self):
        if self.fail:
            raise ValueError("state mismatch")
        return {"access_token": access_token(self.roles, NOW + self.exp_in, self.username), "id_token": "ID.TOKEN",
                "refresh_token": "REFRESH", "userinfo": {"sub": f"id-{self.username}", "preferred_username": self.username,
                                                         "name": self.username.title()}}

    def load_server_metadata(self):
        if not self.metadata:
            raise ConnectionError("down")
        return {"end_session_endpoint": "http://kc/logout", "token_endpoint": "http://kc/token"}


class FakeHttp:
    """Routes: GET/request to the API and POST to the token endpoint."""

    def __init__(self, api_status=200, api_body=None, refresh_ok=True, exc=None, refresh_exp_in=300):
        self.api_status, self.api_body, self.refresh_ok, self.exc = api_status, api_body or {"ok": True}, refresh_ok, exc
        self.refresh_exp_in, self.calls = refresh_exp_in, []

    def _resp(self, status, body):
        def raise_for_status():
            if status >= 400:
                raise requests.HTTPError(f"HTTP {status}")
        return SimpleNamespace(status_code=status, json=lambda: body, text="plain", content=b"x",
                               raise_for_status=raise_for_status)

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if self.exc:
            raise self.exc
        return self._resp(self.api_status, self.api_body)

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        self.calls.append(("POST", url, kw))
        if kw["data"]["grant_type"] == "client_credentials":
            return self._resp(200, {"access_token": "S2S", "expires_in": 300})
        if not self.refresh_ok:
            return self._resp(400, {})
        return self._resp(200, {"access_token": access_token(["app-user"], NOW + self.refresh_exp_in),
                                "refresh_token": "REFRESH2", "id_token": "ID2"})


class FakeSync:
    last_error = None
    last_run_ms = None

    def __init__(self, added=2, error=None):
        self.added, self.error, self.runs = added, error, 0

    def run_safely(self):
        self.runs += 1
        self.last_error = self.error
        return self.added


@pytest.fixture
def ctx():
    store = Store("sqlite:///:memory:")
    store.init_schema()
    return SimpleNamespace(store=store, clock=Clock(), kc=FakeKeycloak(), http=FakeHttp(), sync=FakeSync())


def build(ctx, **overrides):
    config = Config.from_env({**ENV, **overrides})
    app = create_app(config, ctx.store, oauth=SimpleNamespace(keycloak=ctx.kc), http=ctx.http, sync=ctx.sync, clock=ctx.clock)
    return app.test_client()


def sign_in(client):
    assert client.get("/callback").status_code == 302


def csrf(client):
    with client.session_transaction() as s:
        return s["csrf"]


def events(ctx, **flt):
    return ctx.store.query_events(flt, 1, 500)[0]


def types(ctx, **flt):
    return [e["event_type"] for e in events(ctx, **flt)]


# ---- authentication ----------------------------------------------------------------------------------------
def test_login_redirects_to_keycloak_with_callback(ctx):
    client = build(ctx)
    assert client.get("/login").status_code == 302 and ctx.kc.redirect_uri == "http://localhost:8083/callback"


def test_anonymous_users_are_sent_to_login(ctx):
    client = build(ctx)
    for path in ("/dashboard", "/admin", "/events.json"):
        assert client.get(path).headers["Location"].endswith("/login")
    assert client.post("/s2s").headers["Location"].endswith("/login")


def test_index_page_and_redirect_when_signed_in(ctx):
    client = build(ctx)
    assert b"Sign in with Keycloak" in client.get("/").data
    sign_in(client)
    assert client.get("/").headers["Location"].endswith("/dashboard")


def test_callback_creates_session_and_logs_login(ctx):
    client = build(ctx)
    sign_in(client)
    login = next(e for e in events(ctx) if e["event_type"] == "LOGIN")
    assert (login["username"], login["source"], login["session_id"]) == ("alice", "app", "kc-sid-1")
    assert "app-user" in login["detail"]
    sess = ctx.store.recent_sessions()[0]
    assert (sess["username"], sess["roles"], sess["logout_at"]) == ("alice", "app-user", None)
    assert sess["access_expires_at"] == int((NOW + 300) * 1000)


def test_tokens_are_not_stored_in_cookie_or_database(ctx):
    client = build(ctx)
    sign_in(client)
    cookie = client.get_cookie("logapp_session").value
    payload = base64.urlsafe_b64decode(cookie.split(".")[0] + "==").decode(errors="ignore")
    for secret in ("REFRESH", "ID.TOKEN", access_token(["app-user"])):
        assert secret not in payload
    assert "REFRESH" not in json.dumps(ctx.store.recent_sessions()) + json.dumps(events(ctx))


def test_failed_callback_is_logged(ctx):
    ctx.kc.fail = True
    client = build(ctx)
    resp = client.get("/callback")
    assert resp.status_code == 302
    failed = next(e for e in events(ctx) if e["event_type"] == "LOGIN_FAILED")
    assert "state mismatch" in failed["error"]
    assert b"Login failed" in client.get("/").data


def test_logout_ends_session_and_redirects_to_keycloak(ctx):
    client = build(ctx)
    sign_in(client)
    resp = client.get("/logout")
    assert resp.headers["Location"].startswith("http://kc/logout?") and "id_token_hint=ID.TOKEN" in resp.headers["Location"]
    assert "LOGOUT" in types(ctx)
    assert ctx.store.recent_sessions()[0]["end_reason"] == "logout"
    assert client.get("/dashboard").headers["Location"].endswith("/login")


def test_logout_without_session_or_with_idp_down(ctx):
    client = build(ctx)
    assert client.get("/logout").status_code == 302 and "LOGOUT" not in types(ctx)
    ctx.kc.metadata = False
    sign_in(client)
    assert client.get("/logout").headers["Location"].endswith("/")
    assert ctx.store.recent_sessions()[0]["end_reason"] == "logout"


def test_second_login_replaces_previous_session(ctx):
    client = build(ctx)
    sign_in(client)
    sign_in(client)
    assert sorted(s["end_reason"] or "" for s in ctx.store.recent_sessions()) == ["", "replaced"]


# ---- access log ----------------------------------------------------------------------------------------------
def test_every_request_is_access_logged_except_health_and_static(ctx):
    client = build(ctx)
    client.get("/")
    client.get("/healthz")
    client.get("/static/style.css")
    client.get("/nope")
    log = [(e["method"], e["path"], e["status"]) for e in events(ctx, kind="access")]
    assert sorted(log) == [("GET", "/", 200), ("GET", "/nope", 404)]
    assert all(e["duration_ms"] is not None for e in events(ctx, kind="access"))


def test_healthz_reports_database(ctx):
    assert build(ctx).get("/healthz").get_json() == {"database": True, "status": "UP"}


def test_logging_failures_never_break_requests(ctx, monkeypatch):
    client = build(ctx)

    def boom(**kw):
        raise RuntimeError("db down")
    monkeypatch.setattr(ctx.store, "add_event", boom)
    assert client.get("/").status_code == 200


# ---- dashboard + filters -------------------------------------------------------------------------------------
def test_dashboard_lists_events_and_session_info(ctx):
    client = build(ctx)
    sign_in(client)
    html = client.get("/dashboard").get_data(as_text=True)
    assert "Signed in as <b>alice</b>" in html and "<code>LOGIN</code>" in html and "Service-to-service call" in html
    assert "Admin</a>" not in html and "Admin" not in html.split("<nav>")[1].split("</nav>")[0]


def test_non_admin_only_sees_own_events_even_when_filtering_for_others(ctx):
    ctx.store.add_event(event_type="LOGIN", kind="auth", source="keycloak", username="bob")
    ctx.store.add_event(event_type="LOGIN", kind="auth", source="keycloak", username="alice")
    client = build(ctx)
    sign_in(client)
    data = client.get("/events.json?username=bob&event_type=LOGIN").get_json()
    assert {e["username"] for e in data["events"]} == {"alice"}


def test_admin_sees_everyone_and_can_filter(ctx):
    ctx.kc = FakeKeycloak("bob", ("app-admin", "app-user"))
    ctx.store.add_event(event_type="LOGIN", kind="auth", source="keycloak", username="alice")
    ctx.store.add_event(event_type="LOGIN_ERROR", kind="auth", source="keycloak", username="mallory", error="bad")
    client = build(ctx)
    sign_in(client)
    all_users = client.get("/events.json?source=keycloak").get_json()
    assert {e["username"] for e in all_users["events"]} == {"alice", "mallory"}
    assert [e["username"] for e in client.get("/events.json?username=mal").get_json()["events"]] == ["mallory"]
    assert [e["event_type"] for e in client.get("/events.json?event_type=LOGIN_ERROR").get_json()["events"]] == ["LOGIN_ERROR"]
    assert "Admin</a>" in client.get("/dashboard").get_data(as_text=True)


def test_status_and_date_filters_on_http_events(ctx):
    client = build(ctx)
    sign_in(client)
    client.get("/nope")
    ok = client.get("/events.json?status=404&kind=access").get_json()
    assert [e["path"] for e in ok["events"]] == ["/nope"]
    assert client.get("/events.json?status=5xx").get_json()["total"] == 0
    assert client.get("/events.json?date_from=2099-01-01").get_json()["total"] == 0
    assert client.get("/events.json?date_from=2000-01-01&date_to=2099-01-01").get_json()["total"] > 0
    assert client.get("/events.json?date_from=bogus&status=bogus").status_code == 200


def test_pagination_and_page_size(ctx):
    client = build(ctx, LOGAPP_PAGE_SIZE="2")
    sign_in(client)
    for _ in range(4):
        ctx.store.add_event(event_type="HTTP_REQUEST", kind="access", username="alice", path="/x", status=200)
    data = client.get("/events.json?kind=access&page=2").get_json()
    assert data["page_size"] == 2 and len(data["events"]) == 2 and data["page"] == 2
    html = client.get("/dashboard?kind=access&page=2").get_data(as_text=True)
    assert "Page 2 of" in html and "Newer" in html and "kind=access" in html


def test_live_mode_adds_refresh_meta(ctx):
    client = build(ctx)
    sign_in(client)
    assert 'http-equiv="refresh"' in client.get("/dashboard?live=1").get_data(as_text=True)
    assert 'http-equiv="refresh"' not in client.get("/dashboard").get_data(as_text=True)


def test_event_values_are_html_escaped(ctx):
    client = build(ctx)
    sign_in(client)
    ctx.store.add_event(event_type="X", kind="access", username="alice", error="<script>alert(1)</script>")
    html = client.get("/dashboard").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


# ---- API calls and service-to-service ---------------------------------------------------------------------------
def test_api_call_uses_user_token_and_is_logged(ctx):
    client = build(ctx)
    sign_in(client)
    resp = client.post("/api-call/me", data={"csrf": csrf(client)})
    assert resp.status_code == 302
    method, url, kw = ctx.http.calls[-1]
    assert (method, url) == ("GET", "http://api:8082/api/me") and kw["headers"]["Authorization"].startswith("Bearer h.")
    call = next(e for e in events(ctx) if e["event_type"] == "API_CALL")
    assert (call["username"], call["path"], call["status"], call["kind"], call["error"]) == ("alice", "/api/me", 200, "api", None)
    assert "HTTP 200" in client.get("/dashboard").get_data(as_text=True)


def test_api_call_failures_are_logged_with_reason(ctx):
    ctx.http = FakeHttp(api_status=403, api_body={"message": "permission denied"})
    client = build(ctx)
    sign_in(client)
    client.post("/api-call/admin", data={"csrf": csrf(client)})
    call = next(e for e in events(ctx) if e["event_type"] == "API_CALL")
    assert (call["status"], call["error"]) == (403, "permission denied")


def test_api_unreachable_is_logged_and_shown(ctx):
    ctx.http = FakeHttp(exc=requests.ConnectionError("refused"))
    client = build(ctx)
    sign_in(client)
    client.post("/api-call/me", data={"csrf": csrf(client)})
    call = next(e for e in events(ctx) if e["event_type"] == "API_CALL")
    assert call["status"] is None and "unreachable" in call["error"]


def test_api_call_requires_csrf_and_known_key(ctx):
    client = build(ctx)
    sign_in(client)
    assert client.post("/api-call/me", data={"csrf": "wrong"}).status_code == 400
    assert client.post("/api-call/nope", data={"csrf": csrf(client)}).status_code == 404
    assert set(API_CALLS) == {"me", "reports", "admin"}


def test_service_to_service_logged_as_service_account(ctx):
    client = build(ctx)
    sign_in(client)
    client.post("/s2s", data={"csrf": csrf(client)})
    assert ctx.http.calls[-1][2]["headers"]["Authorization"] == "Bearer S2S"
    e = next(e for e in events(ctx) if e["kind"] == "s2s")
    assert (e["event_type"], e["username"], e["client_id"], e["path"], e["status"]) == \
           ("S2S_REQUEST", "service-account-demo-service", "demo-service", "/api/service/data", 200)
    assert json.loads(e["detail"]) == {"triggered_by": "alice"}


def test_service_to_service_errors(ctx):
    ctx.http = FakeHttp(api_status=401, api_body={"message": "invalid token"})
    client = build(ctx)
    sign_in(client)
    client.post("/s2s", data={"csrf": csrf(client)})
    e = next(e for e in events(ctx) if e["kind"] == "s2s")
    assert (e["event_type"], e["status"], e["error"]) == ("S2S_ERROR", 401, "invalid token")
    ctx.http = FakeHttp(exc=requests.ConnectionError("refused"))
    client = build(ctx)
    sign_in(client)
    client.post("/s2s", data={"csrf": csrf(client)})
    assert any(e["event_type"] == "S2S_ERROR" and e["status"] is None for e in events(ctx, kind="s2s"))
    assert client.post("/s2s", data={"csrf": "bad"}).status_code == 400


# ---- token lifecycle ------------------------------------------------------------------------------------------
def test_expiry_warning_then_automatic_refresh(ctx):
    client = build(ctx)
    sign_in(client)
    ctx.clock.now += 250  # 50 s left <= 60 s warning threshold
    assert client.get("/dashboard").status_code == 200
    assert "TOKEN_EXPIRY_WARNING" in types(ctx) and "TOKEN_REFRESH" in types(ctx)
    refresh = next(e for e in events(ctx) if e["event_type"] == "TOKEN_REFRESH")
    assert json.loads(refresh["detail"])["reason"] == "auto"
    assert ctx.store.recent_sessions()[0]["refreshes"] == 1
    grant = [c[2]["data"] for c in ctx.http.calls if c[0] == "POST"][-1]
    assert grant["grant_type"] == "refresh_token" and grant["refresh_token"] == "REFRESH"


def test_no_warning_while_token_is_fresh(ctx):
    client = build(ctx)
    sign_in(client)
    ctx.clock.now += 100
    client.get("/dashboard")
    assert "TOKEN_EXPIRY_WARNING" not in types(ctx)


def test_refresh_failure_before_expiry_keeps_session_but_logs(ctx):
    ctx.http = FakeHttp(refresh_ok=False)
    client = build(ctx)
    sign_in(client)
    ctx.clock.now += 250
    assert client.get("/dashboard").status_code == 200
    assert "TOKEN_REFRESH_FAILED" in types(ctx) and "TOKEN_EXPIRED" not in types(ctx)
    client.get("/dashboard")                      # one warning per access token, failures are retried
    assert types(ctx).count("TOKEN_EXPIRY_WARNING") == 1 and types(ctx).count("TOKEN_REFRESH_FAILED") == 2


def test_expired_token_that_cannot_be_refreshed_ends_the_session(ctx):
    ctx.http = FakeHttp(refresh_ok=False)
    client = build(ctx)
    sign_in(client)
    ctx.clock.now += 400
    resp = client.get("/dashboard")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/")
    assert "TOKEN_EXPIRED" in types(ctx) and ctx.store.recent_sessions()[0]["end_reason"] == "token_expired"
    assert client.get("/dashboard").headers["Location"].endswith("/login")


def test_expired_token_is_refreshed_when_possible(ctx):
    client = build(ctx)
    sign_in(client)
    ctx.clock.now += 400
    assert client.get("/dashboard").status_code == 200 and "TOKEN_EXPIRED" not in types(ctx)


def test_server_restart_ends_sessions_without_tokens(ctx):
    client = build(ctx)
    sign_in(client)
    with client.session_transaction() as s:
        s["sid"] = "unknown-sid"
    ctx.store.start_session("unknown-sid", username="alice", user_id=None, kc_session_id=None, roles=[], ip=None,
                            access_expires_at=None, now=1)
    assert client.get("/dashboard").status_code == 302
    assert ctx.store.get_session("unknown-sid")["end_reason"] == "server_restart"


# ---- admin panel -------------------------------------------------------------------------------------------------
def test_admin_panel_forbidden_for_normal_users_and_audited(ctx):
    client = build(ctx)
    sign_in(client)
    resp = client.get("/admin")
    assert resp.status_code == 403 and b"app-admin" in resp.data
    assert "ACCESS_DENIED" in types(ctx)
    assert ctx.store.recent_audit()[0]["outcome"] == "denied"
    assert client.post("/admin/sync", data={"csrf": csrf(client)}).status_code == 403
    assert ctx.sync.runs == 0


def test_admin_panel_shows_statistics(ctx):
    ctx.kc = FakeKeycloak("bob", ("app-admin", "app-user"))
    now_ms = int(NOW * 1000)
    for user, n in (("alice", 3), ("carol", 1)):
        for i in range(n):
            ctx.store.add_event(event_type="LOGIN", kind="auth", source="keycloak", username=user, ts=now_ms - 1000 * i)
    ctx.store.add_event(event_type="LOGIN_ERROR", kind="auth", source="keycloak", username="eve", ts=now_ms)
    client = build(ctx)
    sign_in(client)
    html = client.get("/admin").get_data(as_text=True)
    assert "Most active users" in html and html.index("alice") < html.index("carol")
    assert "Failed attempts" in html and "Active sessions" in html
    assert "view admin panel" in client.get("/admin?range=30d").get_data(as_text=True)  # audit trail visible
    assert client.get("/admin?range=bogus").status_code == 200


def test_admin_manual_sync(ctx):
    ctx.kc = FakeKeycloak("bob", ("app-admin",))
    client = build(ctx)
    sign_in(client)
    assert client.post("/admin/sync", data={"csrf": "x"}).status_code == 400
    resp = client.post("/admin/sync", data={"csrf": csrf(client)}, follow_redirects=True)
    assert ctx.sync.runs == 1 and b"2 new event" in resp.data
    ctx.sync.error = "HTTPError: 401"
    resp = client.post("/admin/sync", data={"csrf": csrf(client)}, follow_redirects=True)
    assert b"Sync failed: HTTPError: 401" in resp.data
    assert "Keycloak event sync: HTTPError" in client.get("/dashboard").get_data(as_text=True)


def test_custom_admin_role(ctx):
    client = build(ctx, LOGAPP_ADMIN_ROLE="app-user")
    sign_in(client)
    assert client.get("/admin").status_code == 200


# ---- configuration --------------------------------------------------------------------------------------------------
def test_secure_cookie_and_proxy_trust_flags(ctx):
    app = create_app(Config.from_env({**ENV, "LOGAPP_PUBLIC_URL": "https://logs.example.com", "LOGAPP_TRUST_PROXY": "true"}),
                     ctx.store, oauth=SimpleNamespace(keycloak=ctx.kc))
    assert app.config["SESSION_COOKIE_SECURE"] is True and app.wsgi_app.__class__.__name__ == "ProxyFix"


def test_build_requires_configuration():
    import log_app
    with pytest.raises(RuntimeError, match="missing environment variables"):
        log_app.build({})


def test_build_wires_store_sync_and_app(tmp_path):
    import log_app
    env = {**ENV, "LOGAPP_DATABASE_URL": f"sqlite:///{tmp_path / 'l.db'}", "LOGAPP_SYNC_INTERVAL": "3600"}
    app = log_app.build(env)
    ext = app.extensions["logapp"]
    try:
        assert ext["store"].ping() and ext["sync"].base == "http://kc/admin/realms/demo"
        assert ext["sync"].tokens.client_id == "demo-logapp"   # event reads use the log app's own service account
        assert ext["sync"].tokens.scope == "kc-admin-api"      # required by the Keycloak 26.8 Admin API audience check
        assert ext["s2s"].client_id == "demo-service"          # the probe uses the demo-service identity
    finally:
        ext["sync"].stop()
