"""Unit tests for logapp/log_helpers.py."""
import base64
import json
from datetime import date

import pytest

from log_helpers import (build_logout_url, day_start_ms, decode_jwt_payload, fmt_day, fmt_ts, page_count,
                         page_number, parse_day, parse_filters, realm_roles, seconds_left, severity)


def jwt_of(payload):
    return "h." + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=") + ".s"


def test_decode_jwt_payload():
    assert decode_jwt_payload(jwt_of({"sub": "x"})) == {"sub": "x"}
    for bad in ("", "abc", "a.!!!.c", None, "a." + base64.urlsafe_b64encode(b"[1]").decode() + ".c"):
        assert decode_jwt_payload(bad) == {}


def test_realm_roles_hides_builtin_roles():
    claims = {"realm_access": {"roles": ["app-user", "offline_access", "uma_authorization", "default-roles-demo"]}}
    assert realm_roles(claims) == ["app-user"] and realm_roles({}) == []


def test_seconds_left():
    assert seconds_left(1000, now=900) == 100 and seconds_left(1000, now=2000) == 0
    assert seconds_left(None) == 0 and seconds_left("x") == 0


def test_build_logout_url():
    url = build_logout_url("http://kc/logout", "IDT", "http://app/", "demo-logapp")
    assert "id_token_hint=IDT" in url and "client_id=demo-logapp" in url and "post_logout_redirect_uri=http%3A%2F%2Fapp%2F" in url
    assert "id_token_hint" not in build_logout_url("http://kc/logout", None, "http://app/", "c")


def test_parse_day():
    assert parse_day("2026-11-18") == date(2026, 11, 18) and parse_day(" 2026-11-18 ") == date(2026, 11, 18)
    assert parse_day("") is None and parse_day(None) is None and parse_day("18/11/2026") is None


def test_day_start_ms_is_utc_midnight():
    assert day_start_ms(date(1970, 1, 2)) == 86_400_000


def test_parse_filters_end_date_is_inclusive():
    f = parse_filters({"date_from": "2026-11-18", "date_to": "2026-11-18"})
    assert f["date_to"] - f["date_from"] == 86_400_000


def test_parse_filters_sanitises_input():
    f = parse_filters({"username": "  alice  ", "event_type": "LOGIN", "status": "4XX", "q": "x" * 500,
                       "date_from": "garbage"})
    assert f["username"] == "alice" and f["status"] == "4xx" and len(f["q"]) == 100 and f["date_from"] is None
    assert parse_filters({"status": "20"})["status"] == "" and parse_filters({"status": "'; --"})["status"] == ""


def test_parse_filters_source_is_whitelisted():
    assert parse_filters({"source": "keycloak"})["source"] == "keycloak"
    assert parse_filters({"source": "evil"})["source"] == ""


def test_parse_filters_pins_username_for_non_admins():
    f = parse_filters({"username": "bob"}, force_username="alice")
    assert f["username_exact"] == "alice" and f["username"] == ""
    assert parse_filters({"username": "bob"})["username_exact"] == ""


def test_paging_helpers():
    assert page_number({"page": "3"}) == 3
    assert page_number({"page": "0"}) == 1 and page_number({"page": "x"}) == 1 and page_number({}) == 1
    assert (page_count(0, 25), page_count(25, 25), page_count(26, 25)) == (1, 1, 2)


def test_formatting():
    assert fmt_ts(None) == "" and fmt_ts(0) == "1970-01-01 00:00:00"
    assert fmt_day(0) == "Thu 01 Jan"


@pytest.mark.parametrize("etype,status,expected", [
    ("LOGIN", None, "ok"), ("LOGIN_ERROR", None, "bad"), ("TOKEN_EXPIRED", None, "bad"),
    ("TOKEN_EXPIRY_WARNING", None, "warn"), ("HTTP_REQUEST", 200, "ok"), ("HTTP_REQUEST", 404, "warn"),
    ("HTTP_REQUEST", 503, "bad"), ("S2S_ERROR", 403, "bad"),
])
def test_severity(etype, status, expected):
    assert severity(etype, status) == expected
