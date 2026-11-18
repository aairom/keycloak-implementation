"""Unit tests for logapp/token_source.py (client credentials cache)."""
from types import SimpleNamespace

import pytest

from token_source import TokenSource


class FakeHttp:
    def __init__(self, expires_in=300, fail=False):
        self.calls, self.expires_in, self.fail, self.n = [], expires_in, fail, 0

    def post(self, url, **kw):
        self.calls.append((url, kw))
        self.n += 1

        def raise_for_status():
            if self.fail:
                raise RuntimeError("401")
        return SimpleNamespace(raise_for_status=raise_for_status,
                               json=lambda: {"access_token": f"tok{self.n}", "expires_in": self.expires_in})


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(http=None, clock=None):
    return TokenSource("http://kc/token", "cid", "secret", http or FakeHttp(), clock=clock or Clock())


def test_token_is_cached_until_close_to_expiry():
    http, clock = FakeHttp(expires_in=300), Clock()
    ts = make(http, clock)
    assert ts.token() == "tok1" and ts.token() == "tok1" and len(http.calls) == 1
    clock.now += 269
    assert ts.token() == "tok1"          # 31 s left: still cached
    clock.now += 2
    assert ts.token() == "tok2"          # inside the 30 s skew: renewed


def test_request_uses_client_credentials():
    http = FakeHttp()
    make(http).token()
    url, kw = http.calls[0]
    assert url == "http://kc/token"
    assert kw["data"] == {"grant_type": "client_credentials", "client_id": "cid", "client_secret": "secret"}


def test_scope_is_sent_only_when_configured():
    http = FakeHttp()
    TokenSource("http://kc/token", "cid", "secret", http, scope="kc-admin-api").token()
    assert http.calls[0][1]["data"]["scope"] == "kc-admin-api"
    http = FakeHttp()
    make(http).token()
    assert "scope" not in http.calls[0][1]["data"]


def test_invalidate_forces_a_new_token():
    ts = make()
    assert ts.token() == "tok1"
    ts.invalidate()
    assert ts.token() == "tok2"


def test_failure_propagates_and_is_not_cached():
    http = FakeHttp(fail=True)
    ts = make(http)
    with pytest.raises(RuntimeError):
        ts.token()
    http.fail = False
    assert ts.token() == "tok2"
