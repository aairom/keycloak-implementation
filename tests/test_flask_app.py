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


def test_main_explains_missing_configuration(monkeypatch, capsys):
    for name in ("SERVER_URL", "REALM", "CLIENT_ID", "REDIRECT_URI"):
        monkeypatch.delenv(f"KEYCLOAK_{name}", raising=False)
    assert flask_app.main() == 2
    err = capsys.readouterr().err
    assert "server_url is required" in err and "run_connector_example.sh" in err and "Traceback" not in err


def test_main_reports_unreachable_keycloak(monkeypatch, capsys):
    from keycloak_connector import DiscoveryError

    def down(_cfg=None):
        raise DiscoveryError("cannot reach Keycloak")
    monkeypatch.setattr(flask_app, "create_app", down)
    assert flask_app.main() == 3
    assert "not reachable" in capsys.readouterr().err


def test_main_starts_the_server(monkeypatch):
    started = {}

    class FakeApp:
        def run(self, host, port):
            started.update(host=host, port=port)
    monkeypatch.setattr(flask_app, "create_app", lambda: FakeApp())
    monkeypatch.setenv("PORT", "9100")
    assert flask_app.main() == 0 and started == {"host": "127.0.0.1", "port": 9100}


def test_secret_key_is_random_when_not_configured(connector, monkeypatch):
    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)
    a, b = flask_app.create_app(connector), flask_app.create_app(connector)
    assert a.secret_key != b.secret_key and len(a.secret_key) == 64
    monkeypatch.setenv("FLASK_SECRET_KEY", "fixed-key-for-test")
    assert flask_app.create_app(connector).secret_key == "fixed-key-for-test"


def test_pages_are_readable_html(client):
    html = client.get("/").get_data(as_text=True)
    assert "<style>" in html and "font:18px" in html and "viewport" in html and "/logout" in html


def test_callback_without_cookie_explains_the_host_name_rule(client):
    resp = client.get("/callback", query_string={"code": "x", "state": "y"})
    body = resp.get_data(as_text=True)
    assert resp.status_code == 400 and "same host name" in body and "https://app.test/callback" in body


def test_failed_callback_shows_and_logs_the_reason(client, fake_kc, caplog):
    location = client.get("/login").headers["Location"]
    params = {**fake_kc.authorize(location), "state": "forged"}
    with caplog.at_level("WARNING", logger="flask_app"):
        resp = client.get("/callback", query_string=params)
    body = resp.get_data(as_text=True)
    assert resp.status_code == 400 and "StateMismatchError" in body and "state of the callback" in body
    assert "StateMismatchError" in caplog.text and "code=" not in caplog.text


def test_keycloak_error_is_shown_escaped(client):
    client.get("/login")
    resp = client.get("/callback", query_string={"error": "<script>x</script>"})
    body = resp.get_data(as_text=True)
    assert resp.status_code == 401 and "<script>x</script>" not in body and "&lt;script&gt;" in body


def test_session_cookie_has_its_own_name(client, fake_kc):
    resp = client.get("/login")
    cookies = resp.headers.getlist("Set-Cookie")
    assert any(c.startswith("connector_example_session=") for c in cookies)
    assert not any(c.startswith("session=") for c in cookies)
