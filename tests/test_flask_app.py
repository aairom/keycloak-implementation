"""The Flask example end to end through its routes, with the connector wired to the offline Keycloak."""
import importlib.util
from pathlib import Path
from urllib.parse import urlparse

import pytest

from conftest import REDIRECT
from keycloak_connector import KeycloakConnector

SPEC = importlib.util.spec_from_file_location(
    "flask_app", Path(__file__).resolve().parents[1] / "connector" / "examples" / "flask_app.py")
flask_app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flask_app)


@pytest.fixture
def client(connector):
    return flask_app.create_app(connector).test_client()


def sign_in(client, fake_kc):
    location = client.get("/login").headers["Location"]
    params = fake_kc.authorize(location)
    return client.get("/callback", query_string=params)


def test_anonymous_user_is_sent_to_login(client):
    assert client.get("/").status_code == 200
    resp = client.get("/profile")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")


def test_login_callback_profile_logout(client, fake_kc):
    assert urlparse(client.get("/login").headers["Location"]).path.endswith("/auth")
    resp = sign_in(client, fake_kc)
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/profile")
    profile = client.get("/profile").get_json()
    assert profile["user"] == "alice" and profile["access_token_expires_in"] > 0
    out = client.get("/logout")
    assert out.status_code == 302 and "id_token_hint" in out.headers["Location"]
    assert client.get("/profile").status_code == 302


def test_callback_without_login_in_progress(client):
    assert client.get("/callback", query_string={"code": "x"}).status_code == 400


def test_callback_with_error_and_with_forged_state(client, fake_kc):
    client.get("/login")
    assert client.get("/callback", query_string={"error": "access_denied"}).status_code == 401
    location = client.get("/login").headers["Location"]
    params = {**fake_kc.authorize(location), "state": "forged"}
    assert client.get("/callback", query_string=params).status_code == 400


def test_expired_session_redirects_to_login(client, fake_kc, connector):
    sign_in(client, fake_kc)
    fake_kc.sessions_ended = True
    connector.clock.advance(280)                      # access token inside the refresh margin -> refresh fails
    resp = client.get("/profile")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")


def test_valid_token_is_refreshed_transparently(client, fake_kc, connector):
    sign_in(client, fake_kc)
    connector.clock.advance(280)
    assert client.get("/profile").status_code == 200


def test_factory_builds_connector_from_environment(monkeypatch, fake_kc):
    monkeypatch.setenv("FLASK_SECRET_KEY", "k" * 32)
    for name, value in {"SERVER_URL": "https://auth.test", "REALM": "demo", "CLIENT_ID": "demo-client",
                        "REDIRECT_URI": REDIRECT}.items():
        monkeypatch.setenv(f"KEYCLOAK_{name}", value)
    monkeypatch.setattr(flask_app, "KeycloakConnector",
                        lambda cfg: KeycloakConnector(cfg, session=fake_kc, sleep=lambda _s: None))
    assert flask_app.create_app().test_client().get("/").status_code == 200
