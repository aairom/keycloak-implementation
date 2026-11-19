"""Unit tests of the live-check helpers in scripts/verify_connector.py (no Keycloak needed)."""
import pytest

import verify_connector as vc
from conftest import KC_BASE, KC_REALM, FakeResponse

FORM = ('<form id="kc-form-login" onsubmit="x" action="https://auth.test/login-actions/authenticate?a=1&amp;b=2" '
        'method="post"></form>')


@pytest.fixture(autouse=True)
def reset_counter():
    vc.FAILED = 0
    yield
    vc.FAILED = 0


def env():
    return {"KC_HOSTNAME": KC_BASE, "DEMO_REALM": KC_REALM, "LOGAPP_PUBLIC_URL": "https://app.test/",
            "LOGAPP_CLIENT_SECRET": "x", "SERVICE_CLIENT_SECRET": "y"}


def test_check_counts_failures(capsys):
    vc.check(True, "good"); vc.check(False, "bad")
    out = capsys.readouterr().out
    assert "PASS  good" in out and "FAIL  bad" in out and vc.FAILED == 1


def test_raises_helper():
    def boom():
        raise ValueError
    assert vc.raises(ValueError, boom) is True
    assert vc.raises(ValueError, lambda: None) is False


def test_make_connector_uses_registered_callback_and_post_logout_uri():
    kc = vc.make_connector(env(), "demo-logapp", "LOGAPP_CLIENT_SECRET", True)
    assert kc.config.redirect_uri == "https://app.test/callback"
    assert kc.config.post_logout_redirect_uri == "https://app.test/"
    assert kc.config.realm == KC_REALM and kc.config.is_confidential


class FakeSession:
    """Replaces requests.Session inside browser_login: serves the login page, then the redirect."""
    def __init__(self, page, post):
        self.page, self.post_response, self.verify, self.cookies = page, post, True, []
        self.posted = None

    def get(self, url, **kw):
        return self.page

    def post(self, url, data=None, **kw):
        self.posted = (url, data)
        return self.post_response


def patch_session(monkeypatch, page, post):
    session = FakeSession(page, post)
    monkeypatch.setattr(vc.requests, "Session", lambda: session)
    return session


class Page(FakeResponse):
    def __init__(self, text, url="https://auth.test/realms/demo/auth", headers=None, status=200):
        super().__init__(status, {}, text=text)
        self.url, self.headers = url, headers or {}


def test_browser_login_returns_callback_parameters(monkeypatch):
    redirect = Page("", headers={"Location": "https://app.test/callback?code=c1&state=s1&iss=i"}, status=302)
    session = patch_session(monkeypatch, Page(FORM), redirect)
    params = vc.browser_login("https://auth.test/auth", "alice", "pw", "https://app.test/callback", True)
    assert params == {"code": "c1", "state": "s1", "iss": "i"}
    assert session.posted[0] == "https://auth.test/login-actions/authenticate?a=1&b=2"      # HTML entities decoded


def test_browser_login_without_form(monkeypatch):
    patch_session(monkeypatch, Page("<html>maintenance</html>"), None)
    with pytest.raises(RuntimeError, match="no Keycloak login form"):
        vc.browser_login("https://auth.test/auth", "alice", "pw", "https://app.test/callback", True)


def test_browser_login_reports_keycloaks_message_on_wrong_password(monkeypatch):
    html = '<span class="kc-feedback-text">Invalid username or password.</span>'
    patch_session(monkeypatch, Page(FORM), Page(html))
    with pytest.raises(RuntimeError, match="Invalid username or password"):
        vc.browser_login("https://auth.test/auth", "alice", "pw", "https://app.test/callback", True)


def test_browser_login_unknown_failure_reports_status(monkeypatch):
    patch_session(monkeypatch, Page(FORM), Page("nothing useful", status=500))
    with pytest.raises(RuntimeError, match="HTTP 500"):
        vc.browser_login("https://auth.test/auth", "alice", "pw", "https://app.test/callback", True)


def test_main_requires_environment(monkeypatch, capsys):
    monkeypatch.setattr(vc, "load_dotenv", lambda _p: None)
    for name in vc.REQUIRED_ENV:
        monkeypatch.delenv(name, raising=False)
    assert vc.main() == 1
    assert "not set" in capsys.readouterr().out


def test_main_runs_with_environment(monkeypatch):
    monkeypatch.setattr(vc, "load_dotenv", lambda _p: None)
    for name in vc.REQUIRED_ENV:
        monkeypatch.setenv(name, "v")
    monkeypatch.setenv("VERIFY_INSECURE", "1")
    seen = {}
    monkeypatch.setattr(vc, "run", lambda e, verify: seen.update(verify=verify) or 0)
    assert vc.main() == 0 and seen["verify"] is False


def test_run_stops_when_keycloak_is_unreachable(monkeypatch, capsys):
    from keycloak_connector import DiscoveryError

    class Down:
        def __init__(self, *a, **k): pass
        def initialize(self): raise DiscoveryError("cannot reach Keycloak")
    monkeypatch.setattr(vc, "make_connector", lambda *a, **k: Down())
    assert vc.run(env(), True) == 1
    assert "FAIL  initialize()" in capsys.readouterr().out
