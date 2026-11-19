"""Unit tests for scripts/verify_logapp.py with a fake dashboard instead of a live stack."""
from types import SimpleNamespace

import pytest
import requests

import verify_logapp as v

BASE = "http://dash.test"
FORM = ('<form id="kc-form-login" class="x" action="http://kc.test/auth?a=1&amp;b=2" method="post">'
        '<input name="username"></form>')


@pytest.fixture(autouse=True)
def reset_failures():
    v.FAILED = 0


class FakeSession:
    """Stands in for requests.Session: GET /login serves the Keycloak form, POST goes to the callback."""

    def __init__(self, post_url=BASE + "/dashboard", form=FORM, post_text=""):
        self.verify, self.cookies, self.posted = True, [], []
        self.post_url, self.form, self.post_text = post_url, form, post_text

    def get(self, url, **kw):
        return SimpleNamespace(text=self.form, url="http://kc.test/login")

    def post(self, url, data=None, **kw):
        self.posted.append((url, data))
        return SimpleNamespace(url=self.post_url, text=self.post_text, status_code=200)


def test_check_counts_failures(capsys):
    v.check(True, "fine")
    v.check(False, "broken")
    out = capsys.readouterr().out
    assert "PASS  fine" in out and "FAIL  broken" in out and v.FAILED == 1


def test_localhost_cookies_are_made_sendable_over_http():
    cookie = SimpleNamespace(secure=True)
    session = SimpleNamespace(cookies=[cookie])
    v._treat_localhost_as_secure(session, "http://localhost:8083")
    assert cookie.secure is False
    cookie.secure = True
    v._treat_localhost_as_secure(session, "https://logs.example.com")  # https keeps Secure cookies
    assert cookie.secure is True


def test_sign_in_posts_credentials_to_the_unescaped_form_action(monkeypatch):
    fake = FakeSession()
    monkeypatch.setattr(v.requests, "Session", lambda: fake)
    assert v.sign_in(BASE, "alice", "pw", verify=False) is fake
    assert fake.verify is False
    assert fake.posted == [("http://kc.test/auth?a=1&b=2", {"username": "alice", "password": "pw"})]


def test_sign_in_accepts_attribute_order_variants(monkeypatch):
    fake = FakeSession(form='<form action="http://kc.test/x" id="kc-form-login">')
    monkeypatch.setattr(v.requests, "Session", lambda: fake)
    v.sign_in(BASE, "a", "b", verify=True)
    assert fake.posted[0][0] == "http://kc.test/x"


def test_sign_in_fails_without_form_or_when_login_is_refused(monkeypatch):
    monkeypatch.setattr(v.requests, "Session", lambda: FakeSession(form="<html>no form</html>"))
    with pytest.raises(RuntimeError, match="no Keycloak login form"):
        v.sign_in(BASE, "a", "b", True)
    monkeypatch.setattr(v.requests, "Session", lambda: FakeSession(post_url="http://kc.test/authenticate?error"))
    with pytest.raises(RuntimeError, match="login of a failed"):
        v.sign_in(BASE, "a", "b", True)


def test_sign_in_failure_quotes_the_message_keycloak_shows():
    page = '<span class="pf-m-error kc-feedback-text"> Invalid username or password. </span>'
    assert v.keycloak_message(page) == "Invalid username or password."
    assert v.keycloak_message("<html>nothing</html>") is None


def test_sign_in_failure_reports_keycloak_reason_and_hides_the_query_string(monkeypatch):
    page = '<span class="kc-feedback-text">Invalid username or password.</span>'
    monkeypatch.setattr(v.requests, "Session", lambda: FakeSession(
        post_url="http://kc.test/authenticate?session_code=SECRETCODE", post_text=page))
    with pytest.raises(RuntimeError) as exc:
        v.sign_in(BASE, "alice", "", True)
    assert 'Keycloak says "Invalid username or password."' in str(exc.value)
    assert "SECRETCODE" not in str(exc.value)


def test_load_dotenv_fills_only_missing_variables(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nVF_NEW=from-file\nVF_KEPT=from-file\nVF_QUOTED=\"a b\"\nnot a pair\n")
    monkeypatch.setenv("VF_KEPT", "from-shell")
    monkeypatch.delenv("VF_NEW", raising=False)
    monkeypatch.delenv("VF_QUOTED", raising=False)
    v.load_dotenv(env)
    assert (v.os.environ["VF_NEW"], v.os.environ["VF_KEPT"], v.os.environ["VF_QUOTED"]) == \
        ("from-file", "from-shell", "a b")
    v.load_dotenv(tmp_path / "missing.env")  # no file: no error
    for name in ("VF_NEW", "VF_QUOTED"):
        v.os.environ.pop(name, None)


def test_main_names_the_missing_passwords_instead_of_trying_an_empty_login(monkeypatch, capsys):
    monkeypatch.setattr(v, "load_dotenv", lambda path: None)
    monkeypatch.delenv("DEMO_USER_PASSWORD", raising=False)
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "x")
    called = []
    monkeypatch.setattr(v.requests, "get", lambda *a, **k: called.append(a))
    assert v.main() == 1
    out = capsys.readouterr().out
    assert "FAIL  DEMO_USER_PASSWORD not set" in out and not called


def test_csrf_and_events_helpers():
    page = SimpleNamespace(text='<input type="hidden" name="csrf" value="tok123">')
    session = SimpleNamespace(get=lambda url, **kw: page if url.endswith("/dashboard")
                              else SimpleNamespace(json=lambda: {"events": [{"x": kw["params"]}]}))
    assert v.csrf_of(session, BASE) == "tok123"
    assert v.events(session, BASE, kind="api") == [{"x": {"kind": "api"}}]


class Dashboard:
    """Minimal in-memory model of the dashboard that the verification script talks to."""

    def __init__(self, healthy=True, sync_works=True):
        self.log, self.healthy, self.sync_works = [], healthy, sync_works

    def session(self, user):
        dash = self

        class Sess:
            signed_out = False

            def get(self, url, params=None, allow_redirects=True, **kw):
                path = url.replace(BASE, "")
                if path == "/dashboard":
                    if self.signed_out:
                        return SimpleNamespace(text="", status_code=302)
                    return SimpleNamespace(text=f'Signed in as <b>{user}</b> name="csrf" value="t"', status_code=200)
                if path == "/events.json":
                    return SimpleNamespace(json=lambda: {"events": dash.query(user, params or {})})
                if path == "/admin":
                    ok = user == "bob"
                    return SimpleNamespace(status_code=200 if ok else 403,
                                           text="Most active users Failed attempts" if ok else "no")
                if path == "/logout":
                    self.signed_out = True
                    dash.log.append({"event_type": "LOGOUT", "username": user, "source": "app", "kind": "auth"})
                    return SimpleNamespace(status_code=302)
                return SimpleNamespace(status_code=404, text="")

            def post(self, url, data=None, **kw):
                path = url.replace(BASE, "")
                if path.startswith("/api-call/"):
                    key = path.rsplit("/", 1)[1]
                    api = {"me": "/api/me", "reports": "/api/reports", "admin": "/api/admin"}[key]
                    status = 403 if (user == "alice" and key == "admin") else 200
                    dash.log.append({"event_type": "API_CALL", "kind": "api", "source": "app", "username": user,
                                     "path": api, "status": status, "duration_ms": 5, "method": "GET"})
                elif path == "/s2s":
                    dash.log.append({"event_type": "S2S_REQUEST", "kind": "s2s", "source": "app", "status": 200,
                                     "username": "service-account-demo-service", "path": "/api/service/data"})
                return SimpleNamespace(status_code=302)
        return Sess()

    def query(self, user, p):
        rows = list(self.log)
        rows += [{"event_type": "LOGIN", "username": u, "source": "app", "kind": "auth"} for u in ("alice", "bob")]
        rows += [{"event_type": "HTTP_REQUEST", "kind": "access", "source": "app", "method": "GET",
                  "path": "/dashboard", "status": 200, "username": user}]
        if user == "bob":
            rows += [{"event_type": "ACCESS_DENIED", "username": "alice", "source": "app", "kind": "auth"}]
            if self.sync_works:
                rows += [{"event_type": "LOGIN", "username": u, "source": "keycloak", "kind": "auth"}
                         for u in ("alice", "bob")]
        out = []
        for r in rows:
            if p.get("kind") and r.get("kind") != p["kind"]:
                continue
            if p.get("source") and r.get("source") != p["source"]:
                continue
            if p.get("event_type") and r["event_type"] != p["event_type"]:
                continue
            if p.get("username") and p["username"] not in (r.get("username") or ""):
                continue
            if user != "bob" and r.get("username") not in (user, None):
                continue
            if p.get("status") and r.get("status") is not None:
                s = p["status"]
                if not (str(r["status"]) == s or (s.endswith("xx") and str(r["status"])[0] == s[0])):
                    continue
            elif p.get("status"):
                continue
            if p.get("date_from") == "2000-01-01":
                continue
            out.append(r)
        return out


def run_main(monkeypatch, dash, capsys, anonymous_redirects=True):
    monkeypatch.setattr(v, "load_dotenv", lambda path: None)  # never read the developer's real .env in unit tests
    monkeypatch.setenv("DEMO_USER_PASSWORD", "test-alice")
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "test-bob")
    monkeypatch.setenv("LOGAPP_PUBLIC_URL", BASE)
    monkeypatch.setattr(v.requests, "get", lambda url, **kw: SimpleNamespace(
        json=lambda: {"database": dash.healthy}, status_code=302, headers={"Location": "/login"}))
    monkeypatch.setattr(v, "sign_in", lambda base, user, pw, verify: dash.session(user))
    monkeypatch.setattr(v.time, "sleep", lambda s: None)
    code = v.main()
    return code, capsys.readouterr().out


def test_main_passes_against_a_healthy_dashboard(monkeypatch, capsys):
    code, out = run_main(monkeypatch, Dashboard(), capsys)
    assert code == 0 and "LOGAPP VERIFY OK" in out and "FAIL" not in out, out
    assert out.count("PASS") >= 20


def test_main_fails_when_keycloak_events_never_arrive(monkeypatch, capsys):
    ticks = iter(range(0, 10_000, 20))
    monkeypatch.setattr(v.time, "time", lambda: next(ticks))
    code, out = run_main(monkeypatch, Dashboard(sync_works=False), capsys)
    assert code == 1 and "FAIL  Keycloak LOGIN events are synchronised" in out and "LOGAPP VERIFY FAILED" in out


def test_main_fails_when_database_is_down(monkeypatch, capsys):
    code, out = run_main(monkeypatch, Dashboard(healthy=False), capsys)
    assert code == 1 and "FAIL  health endpoint reports the database" in out


def test_main_reports_login_problems(monkeypatch, capsys):
    monkeypatch.setattr(v, "load_dotenv", lambda path: None)
    monkeypatch.setenv("DEMO_USER_PASSWORD", "test-alice")
    monkeypatch.setenv("DEMO_ADMIN_PASSWORD", "test-bob")
    monkeypatch.setenv("LOGAPP_PUBLIC_URL", BASE)
    monkeypatch.setattr(v.requests, "get", lambda url, **kw: SimpleNamespace(
        json=lambda: {"database": True}, status_code=302, headers={"Location": "/login"}))

    def refuse(*a):
        raise RuntimeError("login of alice failed")
    monkeypatch.setattr(v, "sign_in", refuse)
    assert v.main() == 1 and "FAIL  login through Keycloak" in capsys.readouterr().out
