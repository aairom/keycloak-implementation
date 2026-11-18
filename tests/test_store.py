"""Unit tests for logapp/store.py (SQLite in memory; the SQL is shared with PostgreSQL)."""
import pytest

from store import DAY_MS, Store, dedupe_key

T0 = 1_700_000_000_000  # fixed "now" in ms


@pytest.fixture
def store():
    s = Store("sqlite:///:memory:")
    s.init_schema()
    return s


def add(store, event_type="LOGIN", ts=T0, **kw):
    kw.setdefault("kind", "auth")
    kw.setdefault("source", "keycloak")
    return store.add_event(event_type=event_type, ts=ts, **kw)


def test_init_schema_is_idempotent_and_ping_works(store):
    store.init_schema()
    assert store.ping() is True


def test_add_and_query_newest_first(store):
    add(store, ts=T0, username="alice")
    add(store, ts=T0 + 1000, username="bob")
    rows, total = store.query_events({})
    assert total == 2 and [r["username"] for r in rows] == ["bob", "alice"]


def test_detail_is_stored_as_json(store):
    add(store, detail={"b": 1, "a": 2})
    assert store.query_events({})[0][0]["detail"] == '{"a": 2, "b": 1}'


def test_unknown_field_is_rejected(store):
    with pytest.raises(ValueError):
        add(store, nope=1)


def test_dedupe_key_prevents_duplicates(store):
    assert add(store, dedupe_key="k1") is True
    assert add(store, dedupe_key="k1") is False
    assert add(store, dedupe_key=None) is True and add(store, dedupe_key=None) is True  # NULLs never collide
    assert store.query_events({})[1] == 3


def test_dedupe_key_helper_is_stable_and_order_sensitive():
    assert dedupe_key("a", None, 1) == dedupe_key("a", None, 1)
    assert dedupe_key("a", "b") != dedupe_key("b", "a")


@pytest.mark.parametrize("flt,expected", [
    ({"username": "ali"}, {"alice"}),
    ({"username": "ALI"}, {"alice"}),                      # case-insensitive substring
    ({"username_exact": "bob"}, {"bob"}),
    ({"username_exact": "bo"}, set()),                       # exact means exact
    ({"event_type": "LOGIN_ERROR"}, {"carol"}),
    ({"kind": "access"}, {"dave"}),
    ({"source": "app"}, {"dave"}),
    ({"status": "404"}, {"dave"}),
    ({"status": "4xx"}, {"dave"}),
    ({"status": "5xx"}, set()),
    ({"q": "REPORTS"}, {"dave"}),                            # path search, case-insensitive
    ({"q": "bad password"}, {"carol"}),                      # error search
])
def test_filters(store, flt, expected):
    add(store, username="alice")
    add(store, username="bob", ts=T0 + 1)
    add(store, "LOGIN_ERROR", username="carol", error="Bad Password", ts=T0 + 2)
    add(store, "HTTP_REQUEST", username="dave", kind="access", source="app", method="GET", path="/api/reports",
        status=404, ts=T0 + 3)
    rows, total = store.query_events(flt)
    assert {r["username"] for r in rows} == expected and total == len(expected)


def test_date_range_is_half_open(store):
    for i in range(3):
        add(store, username=f"u{i}", ts=T0 + i * DAY_MS)
    rows, _ = store.query_events({"date_from": T0 + DAY_MS, "date_to": T0 + 2 * DAY_MS})
    assert [r["username"] for r in rows] == ["u1"]


def test_invalid_status_filter_is_ignored(store):
    add(store, username="alice")
    assert store.query_events({"status": "abc"})[1] == 1


def test_pagination(store):
    for i in range(5):
        add(store, username=f"u{i}", ts=T0 + i)
    page2, total = store.query_events({}, page=2, page_size=2)
    assert total == 5 and [r["username"] for r in page2] == ["u2", "u1"]
    assert store.query_events({}, page=0, page_size=2)[0][0]["username"] == "u4"  # page < 1 clamps to 1


def test_filters_cannot_inject_sql(store):
    add(store, username="alice")
    rows, total = store.query_events({"username": "x' OR '1'='1", "q": "'; DROP TABLE app_events;--"})
    assert total == 0 and store.query_events({})[1] == 1


def test_event_types_distinct_sorted(store):
    add(store, "LOGOUT")
    add(store, "LOGIN")
    add(store, "LOGIN")
    assert store.event_types() == ["LOGIN", "LOGOUT"]


def test_username_for_user_id_uses_latest_known_name(store):
    add(store, user_id="u1", username="alice-old", ts=T0)
    add(store, user_id="u1", username="alice", ts=T0 + 1)
    add(store, user_id="u2", username=None, ts=T0 + 2)
    assert store.username_for_user_id("u1") == "alice"
    assert store.username_for_user_id("u2") is None
    assert store.username_for_user_id("missing") is None


def test_session_lifecycle(store):
    store.start_session("s1", username="alice", user_id="u1", kc_session_id="k1", roles=["app-user"], ip="1.2.3.4",
                        access_expires_at=T0 + 300_000, now=T0)
    store.touch_session("s1", T0 + 10, access_expires_at=T0 + 600_000, refreshed=True)
    s = store.get_session("s1")
    assert (s["last_seen_at"], s["refreshes"], s["access_expires_at"], s["roles"]) == (T0 + 10, 1, T0 + 600_000, "app-user")
    store.touch_session("s1", T0 + 20)  # plain touch keeps expiry and refresh count
    s = store.get_session("s1")
    assert (s["last_seen_at"], s["refreshes"], s["access_expires_at"]) == (T0 + 20, 1, T0 + 600_000)
    store.end_session("s1", T0 + 30, "logout")
    store.end_session("s1", T0 + 40, "again")  # first end reason wins
    store.touch_session("s1", T0 + 50)         # ended sessions are not touched
    s = store.get_session("s1")
    assert (s["logout_at"], s["end_reason"], s["last_seen_at"]) == (T0 + 30, "logout", T0 + 20)
    assert store.get_session("nope") is None
    assert [r["sid"] for r in store.recent_sessions()] == ["s1"]


def test_audit_log_newest_first(store):
    store.audit("bob", "view admin panel", "ok", now=T0)
    store.audit("alice", "GET /admin", "denied", target="x", ip="1.1.1.1", now=T0 + 1)
    rows = store.recent_audit()
    assert [(r["actor"], r["outcome"]) for r in rows] == [("alice", "denied"), ("bob", "ok")]


def test_state_roundtrip_and_overwrite(store):
    assert store.get_state("w") is None and store.get_state("w", "0") == "0"
    store.set_state("w", "1")
    store.set_state("w", "2")
    assert store.get_state("w") == "2"


def test_stats_aggregates(store):
    now = T0 + 6 * DAY_MS
    add(store, "LOGIN", username="alice", ts=now - 1000)
    add(store, "LOGIN", username="alice", ts=now - 2000)
    add(store, "LOGIN", username="bob", ts=now - 3000)
    add(store, "LOGIN", username="old", ts=now - 20 * DAY_MS)                      # outside the range
    add(store, "LOGIN_ERROR", username="eve", ts=now - 4000)
    add(store, "LOGIN", username="appuser", source="app", ts=now - 500)             # app-side login: not a Keycloak login
    add(store, "TOKEN_REFRESH", kind="token", source="app", ts=now - 100)
    add(store, "TOKEN_EXPIRY_WARNING", kind="token", source="app", ts=now - 100)
    add(store, "HTTP_REQUEST", kind="access", source="app", status=200, duration_ms=10, ts=now - 100)
    add(store, "HTTP_REQUEST", kind="access", source="app", status=500, duration_ms=30, ts=now - 100)
    add(store, "S2S_REQUEST", kind="s2s", source="app", status=200, duration_ms=20, ts=now - 100)
    store.start_session("live", username="a", user_id=None, kc_session_id=None, roles=[], ip=None,
                        access_expires_at=None, now=now - 60_000)
    store.start_session("idle", username="b", user_id=None, kc_session_id=None, roles=[], ip=None,
                        access_expires_at=None, now=now - 3_600_000)
    store.start_session("done", username="c", user_id=None, kc_session_id=None, roles=[], ip=None,
                        access_expires_at=None, now=now - 1000)
    store.end_session("done", now, "logout")

    s = store.stats(now - 7 * DAY_MS, now, idle_ms=30 * 60_000, days=7)
    assert (s["total_logins"], s["failed_logins"], s["app_logins"]) == (3, 1, 1)
    assert (s["token_refreshes"], s["expiry_warnings"], s["s2s_requests"]) == (1, 1, 1)
    assert (s["http_requests"], s["http_errors"], s["avg_duration_ms"]) == (3, 1, 20.0)
    assert s["active_sessions"] == 1
    assert s["top_users"] == [{"username": "alice", "logins": 2}, {"username": "bob", "logins": 1}]
    assert len(s["daily"]) == 7 and sum(d["logins"] for d in s["daily"]) == 3
    assert sum(d["failed"] for d in s["daily"]) == 1
    assert s["daily"][-1]["day_ms"] == now // DAY_MS * DAY_MS


def test_stats_on_empty_database(store):
    s = store.stats(0, T0, 1000)
    assert s["total_logins"] == 0 and s["avg_duration_ms"] == 0 and s["top_users"] == []


def test_postgres_flavour_translation():
    s = Store("postgresql://u:p@h/db")
    assert s.postgres and s._sql("SELECT ? , ?") == "SELECT %s , %s"
    assert "GENERATED ALWAYS AS IDENTITY" in "".join(__import__("store")._ddl(True))


def test_sqlite_file_path(tmp_path):
    path = tmp_path / "x.db"
    s = Store(f"sqlite:///{path}")
    s.init_schema()
    add(s, username="alice")
    assert Store(f"sqlite:///{path}").query_events({})[1] == 1
