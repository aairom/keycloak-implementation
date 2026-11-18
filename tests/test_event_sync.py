"""Unit tests for logapp/event_sync.py (Keycloak event pull)."""
from types import SimpleNamespace

import pytest
import requests

import event_sync
from event_sync import KeycloakEventSync, normalize
from store import Store

T0 = 1_700_000_000_000


@pytest.fixture
def store():
    s = Store("sqlite:///:memory:")
    s.init_schema()
    return s


class Tokens:
    def __init__(self):
        self.invalidated = 0

    def token(self):
        return "ADMIN-TOKEN"

    def invalidate(self):
        self.invalidated += 1


class FakeHttp:
    """Serves ``events`` honouring first/max like the Keycloak admin API."""

    def __init__(self, events=(), status=200):
        self.events, self.status, self.calls = list(events), status, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, dict(params), headers))
        page = self.events[params["first"]:params["first"] + params["max"]]

        def raise_for_status():
            if self.status >= 400:
                raise requests.HTTPError(str(self.status))
        return SimpleNamespace(status_code=self.status, json=lambda: page, raise_for_status=raise_for_status)


def kc_event(i=0, **kw):
    e = {"time": T0 + i, "type": "LOGIN", "clientId": "demo-webapp", "userId": "u1", "sessionId": "s1",
         "ipAddress": "10.0.0.1", "details": {"username": "alice", "code_id": f"c{i}"}}
    e.update(kw)
    return e


def test_normalize_maps_keycloak_fields(store):
    row = normalize(kc_event(), store)
    assert (row["ts"], row["source"], row["kind"], row["event_type"]) == (T0, "keycloak", "auth", "LOGIN")
    assert (row["username"], row["user_id"], row["client_id"], row["session_id"], row["ip"]) == \
           ("alice", "u1", "demo-webapp", "s1", "10.0.0.1")
    assert row["detail"] == {"code_id": "c0"} and row["error"] is None and len(row["dedupe_key"]) == 40


def test_normalize_resolves_username_from_known_user_id(store):
    store.add_event(event_type="LOGIN", kind="auth", user_id="u9", username="carol")
    row = normalize(kc_event(userId="u9", details={}), store)
    assert row["username"] == "carol" and row["detail"] is None


def test_normalize_names_service_accounts(store):
    row = normalize({"time": T0, "type": "CLIENT_LOGIN", "clientId": "demo-service"}, store)
    assert row["username"] == "service-account-demo-service"
    assert normalize({"time": T0, "type": "LOGIN_ERROR", "error": "user_not_found"}, store)["username"] is None


def test_dedupe_key_differs_for_different_events(store):
    assert normalize(kc_event(0), store)["dedupe_key"] != normalize(kc_event(1), store)["dedupe_key"]
    assert normalize(kc_event(0), store)["dedupe_key"] == normalize(kc_event(0), store)["dedupe_key"]


def test_sync_stores_events_and_sets_watermark(store):
    http = FakeHttp([kc_event(0), kc_event(5, type="LOGOUT")])
    sync = KeycloakEventSync(store, Tokens(), "http://kc/admin/realms/demo", http=http)
    assert sync.sync_once() == 2
    assert store.get_state(event_sync.STATE_KEY) == str(T0 + 5)
    url, params, headers = http.calls[0]
    assert url == "http://kc/admin/realms/demo/events" and headers["Authorization"] == "Bearer ADMIN-TOKEN"
    assert params["dateFrom"] == "1970-01-01"     # first run: from the beginning
    sync.sync_once()
    assert http.calls[-1][1]["dateFrom"] == "2023-11-14"  # then from the day of the watermark


def test_resync_creates_no_duplicates(store):
    sync = KeycloakEventSync(store, Tokens(), "http://kc/a", http=FakeHttp([kc_event(0), kc_event(1)]))
    assert sync.sync_once() == 2 and sync.sync_once() == 0
    assert store.query_events({})[1] == 2


def test_sync_pages_through_large_result_sets(store, monkeypatch):
    monkeypatch.setattr(event_sync, "PAGE", 2)
    http = FakeHttp([kc_event(i) for i in range(5)])
    assert KeycloakEventSync(store, Tokens(), "http://kc/a", http=http).sync_once() == 5
    assert [c[1]["first"] for c in http.calls] == [0, 2, 4]


def test_events_without_time_are_skipped(store):
    sync = KeycloakEventSync(store, Tokens(), "http://kc/a", http=FakeHttp([{"type": "LOGIN"}, kc_event(0)]))
    assert sync.sync_once() == 1


def test_run_safely_reports_errors_instead_of_raising(store):
    tokens = Tokens()
    sync = KeycloakEventSync(store, tokens, "http://kc/a", http=FakeHttp(status=401))
    assert sync.run_safely() == 0
    assert "HTTPError" in sync.last_error and sync.last_run_ms and tokens.invalidated == 1


def test_run_safely_clears_a_previous_error(store):
    http = FakeHttp(status=500)
    sync = KeycloakEventSync(store, Tokens(), "http://kc/a", http=http)
    sync.run_safely()
    http.status, http.events = 200, [kc_event(0)]
    assert sync.run_safely() == 1 and sync.last_error is None


def test_background_thread_runs_and_stops(store):
    sync = KeycloakEventSync(store, Tokens(), "http://kc/a", http=FakeHttp([kc_event(0)]), interval=0.01)
    sync.start()
    sync.start()  # second start is a no-op
    for _ in range(200):
        if store.query_events({})[1]:
            break
        import time
        time.sleep(0.01)
    sync.stop()
    sync._thread.join(timeout=2)
    assert store.query_events({})[1] == 1 and not sync._thread.is_alive()
