"""Unit tests for webapp/app.py using a stubbed Authlib client and a stubbed HTTP layer."""
import base64
import json
from types import SimpleNamespace

import pytest
import requests
from flask import redirect

from app import API_CALLS, REQUIRED, create_app

ENV = {
    "OIDC_DISCOVERY_URL": "http://kc/.well-known/openid-configuration",
    "OIDC_CLIENT_ID": "demo-webapp", "OIDC_CLIENT_SECRET": "s3cr3t-value",
    "WEBAPP_SESSION_SECRET": "session-secret-value", "WEBAPP_PUBLIC_URL": "http://localhost:8081/",
    "API_BASE_URL": "http://api:8082/",
}


def _jwt(payload):
    enc = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"h.{enc}.s"


class FakeKeycloak:
    """Mimics the parts of the Authlib Flask client the app uses."""

    def __init__(self, fail=False, metadata=True):
        self.fail, self.metadata = fail, metadata
        self.redirect_uri = None

    def authorize_redirect(self, redirect_uri):
        self.redirect_uri = redirect_uri
        return redirect("http://kc/auth?code_challenge_method=S256")

    def authorize_access_token(self):
        if self.fail:
            raise ValueError("state mismatch")
        return {
            "access_token": _jwt({"exp": 4102444800, "groups": ["managers"],
                                  "realm_access": {"roles": ["app-admin", "app-user", "offline_access"]}}),
            "id_token": "ID.TOKEN.X", "refresh_token": "r",
            "userinfo": {"sub": "u1", "preferred_username": "bob", "name": "Bob Manager",
                         "email": "bob@example.com"},
        }

    def load_server_metadata(self):
        if not self.metadata:
            raise ConnectionError("down")
        return {"end_session_endpoint": "http://kc/logout"}


class FakeHttp:
    def __init__(self, status=200, body=None, exc=None):
        self.status, self.body, self.exc, self.calls = status, body or {"ok": True}, exc, []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        if self.exc:
            raise self.exc
        return SimpleNamespace(status_code=self.status, json=lambda: self.body, text="plain")


def make_client(kc=None, http=None):
    kc = kc or FakeKeycloak()
    app = create_app(env=ENV, oauth=SimpleNamespace(keycloak=kc), http=http or FakeHttp())
    return app.test_client(), kc


def login(client):
    return client.get("/callback?code=abc&state=xyz")


def test_missing_configuration_is_reported():
    for key in REQUIRED:
        env = {k: v for k, v in ENV.items() if k != key}
        with pytest.raises(RuntimeError, match=key):
            create_app(env=env, oauth=SimpleNamespace(keycloak=FakeKeycloak()))


def test_home_page_for_anonymous_user():
    client, _ = make_client()
    body = client.get("/").get_data(as_text=True)
    assert "Sign in" in body and "alice" in body


def test_healthz():
    assert make_client()[0].get("/healthz").get_json() == {"status": "UP"}


def test_login_redirects_with_normalised_callback_url():
    client, kc = make_client()
    resp = client.get("/login")
    assert resp.status_code == 302 and "code_challenge_method=S256" in resp.location
    assert kc.redirect_uri == "http://localhost:8081/callback"


def test_profile_requires_login():
    client, _ = make_client()
    assert client.get("/profile").location.endswith("/login")


def test_callback_creates_session_and_profile_shows_roles():
    client, _ = make_client()
    assert login(client).location.endswith("/profile")
    page = client.get("/profile").get_data(as_text=True)
    assert "Bob Manager" in page and "app-admin" in page and "managers" in page
    assert "offline_access" not in page.split("Realm roles")[1].split("</dd>")[0]


def test_failed_callback_flashes_error_and_stays_anonymous():
    client, _ = make_client(FakeKeycloak(fail=True))
    resp = login(client)
    assert resp.location.endswith("/")
    assert "Login failed" in client.get("/").get_data(as_text=True)
    assert client.get("/profile").location.endswith("/login")


def _csrf(client):
    with client.session_transaction() as s:
        return s["csrf"]


def test_api_call_forwards_bearer_token_and_shows_result():
    http = FakeHttp(200, {"reports": []})
    client, _ = make_client(http=http)
    login(client)
    resp = client.post("/api-call/reports_read", data={"csrf": _csrf(client)})
    assert resp.location.endswith("/profile")
    method, url, kw = http.calls[0]
    assert (method, url) == ("GET", "http://api:8082/api/reports")
    assert kw["headers"]["Authorization"].startswith("Bearer h.")
    page = client.get("/profile").get_data(as_text=True)
    assert "HTTP 200" in page and "Read reports" in page
    assert "HTTP 200" not in client.get("/profile").get_data(as_text=True)  # result is shown once


def test_api_call_denied_status_is_displayed():
    client, _ = make_client(http=FakeHttp(403, {"error": "forbidden"}))
    login(client)
    client.post("/api-call/admin", data={"csrf": _csrf(client)})
    page = client.get("/profile").get_data(as_text=True)
    assert "HTTP 403" in page and "denied" in page


def test_api_unreachable_is_reported():
    client, _ = make_client(http=FakeHttp(exc=requests.ConnectionError("refused")))
    login(client)
    client.post("/api-call/me", data={"csrf": _csrf(client)})
    assert "API unreachable" in client.get("/profile").get_data(as_text=True)


def test_api_call_rejects_bad_csrf_unknown_key_and_anonymous():
    client, _ = make_client()
    assert client.post("/api-call/me", data={"csrf": "x"}).location.endswith("/login")
    login(client)
    assert client.post("/api-call/me", data={"csrf": "wrong"}).status_code == 400
    assert client.post("/api-call/nope", data={"csrf": _csrf(client)}).status_code == 404
    assert client.get("/api-call/me").status_code == 405


def test_logout_clears_session_and_redirects_to_keycloak():
    client, _ = make_client()
    login(client)
    resp = client.get("/logout")
    assert resp.location.startswith("http://kc/logout?") and "id_token_hint=ID.TOKEN.X" in resp.location
    assert client.get("/profile").location.endswith("/login")


def test_logout_when_keycloak_is_down_still_clears_session():
    client, _ = make_client(FakeKeycloak(metadata=False))
    login(client)
    assert client.get("/logout").location.endswith("/")
    assert client.get("/profile").location.endswith("/login")


def test_every_api_call_has_method_path_label():
    assert all(len(v) == 3 and v[1].startswith("/api/") for v in API_CALLS.values())
