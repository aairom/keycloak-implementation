"""Unit tests for service/service_client.py (HTTP layer stubbed)."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service"))
from service_client import ServiceClient, from_env, main  # noqa: E402


class FakeHttp:
    def __init__(self, expires_in=300):
        self.expires_in, self.posts, self.gets, self.n = expires_in, [], [], 0

    def post(self, url, **kw):
        self.n += 1
        self.posts.append((url, kw))
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {"access_token": f"tok{self.n}", "expires_in": self.expires_in})

    def get(self, url, **kw):
        self.gets.append((url, kw))
        return SimpleNamespace(ok=True, status_code=200, json=lambda: {"data": []})


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(http, clock=None):
    return ServiceClient("https://kc/token", "demo-service", "shh", "https://api/", http=http,
                         clock=clock or Clock())


def test_requests_client_credentials_token_and_sends_bearer():
    http = FakeHttp()
    resp = make(http).get("/api/service/data")
    assert resp.status_code == 200
    url, kw = http.posts[0]
    assert url == "https://kc/token"
    assert kw["data"] == {"grant_type": "client_credentials", "client_id": "demo-service",
                          "client_secret": "shh"}
    assert http.gets[0][0] == "https://api/api/service/data"
    assert http.gets[0][1]["headers"] == {"Authorization": "Bearer tok1"}


def test_token_is_cached_until_close_to_expiry():
    http, clock = FakeHttp(expires_in=300), Clock()
    client = make(http, clock)
    assert client.token() == client.token() == "tok1"
    clock.now += 269          # 31 s left, outside the 30 s skew
    assert client.token() == "tok1"
    clock.now += 2            # 29 s left: refresh
    assert client.token() == "tok2" and len(http.posts) == 2


def test_failed_token_request_raises():
    def boom():
        raise RuntimeError("401")
    http = SimpleNamespace(post=lambda *a, **k: SimpleNamespace(raise_for_status=boom))
    with pytest.raises(RuntimeError):
        make(http).token()


ENV = {"KC_HOSTNAME": "https://kc/", "SERVICE_CLIENT_SECRET": "s", "API_PUBLIC_URL": "https://api",
       "DEMO_REALM": "r1"}


def test_from_env_builds_realm_token_url():
    c = from_env(ENV)
    assert c.token_url == "https://kc/realms/r1/protocol/openid-connect/token"
    assert c.client_id == "demo-service"


def test_from_env_reports_missing_variables():
    with pytest.raises(SystemExit, match="SERVICE_CLIENT_SECRET"):
        from_env({k: v for k, v in ENV.items() if k != "SERVICE_CLIENT_SECRET"})


def test_main_prints_result_and_returns_exit_code(monkeypatch, capsys):
    import service_client
    monkeypatch.setattr(service_client, "from_env", lambda: make(FakeHttp()))
    assert main() == 0
    assert "HTTP 200" in capsys.readouterr().out
