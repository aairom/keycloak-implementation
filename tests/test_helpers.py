"""Unit tests for webapp/helpers.py."""
import base64
import json

from helpers import build_logout_url, decode_jwt_payload, realm_roles, seconds_left


def _jwt(payload: dict) -> str:
    enc = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"e30.{enc}.sig"


def test_decode_payload_roundtrip():
    assert decode_jwt_payload(_jwt({"sub": "1", "n": "é"})) == {"sub": "1", "n": "é"}


def test_decode_payload_tolerates_garbage():
    for bad in ("", "abc", "a.b.c", "a..c", None, _jwt([1, 2]).replace("[", "")):
        assert decode_jwt_payload(bad) == {}


def test_decode_payload_rejects_non_object_payload():
    enc = base64.urlsafe_b64encode(b"[1,2]").decode().rstrip("=")
    assert decode_jwt_payload(f"x.{enc}.y") == {}


def test_realm_roles_hides_builtin_roles():
    claims = {"realm_access": {"roles": ["offline_access", "uma_authorization", "default-roles-demo",
                                          "app-user", "app-admin"]}}
    assert realm_roles(claims) == ["app-admin", "app-user"]


def test_realm_roles_missing_claim():
    assert realm_roles({}) == []


def test_seconds_left():
    assert seconds_left({"exp": 1100}, now=1000) == 100
    assert seconds_left({"exp": 900}, now=1000) == 0
    assert seconds_left({}, now=1000) == 0
    assert seconds_left({"exp": "soon"}, now=1000) == 0


def test_logout_url_with_and_without_id_token():
    url = build_logout_url("https://kc/logout", "IDT", "http://app/", "demo-webapp")
    assert url.startswith("https://kc/logout?")
    assert "id_token_hint=IDT" in url and "client_id=demo-webapp" in url
    assert "post_logout_redirect_uri=http%3A%2F%2Fapp%2F" in url
    assert "id_token_hint" not in build_logout_url("https://kc/logout", None, "http://app/", "c")
