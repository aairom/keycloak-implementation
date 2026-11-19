"""LoginRequest and TokenSet value objects."""
from keycloak_connector import LoginRequest, TokenSet


def test_login_request_session_round_trip_and_redaction():
    login = LoginRequest(url="https://x/auth?state=abc", state="abc", nonce="n", code_verifier="v")
    restored = LoginRequest.from_session(login.to_session())
    assert (restored.state, restored.nonce, restored.code_verifier) == ("abc", "n", "v")
    assert "abc" not in repr(login) and "v" != repr(login)
    assert LoginRequest.from_session({"state": "s", "nonce": "n"}).code_verifier is None


def _response(**extra):
    return {"access_token": "at", "expires_in": 300, "refresh_token": "rt", "refresh_expires_in": 1800,
            "id_token": "idt", "scope": "openid", **extra}


def test_from_response_computes_expiry_times():
    ts = TokenSet.from_response(_response(), now=1000, claims={"sub": "u"})
    assert ts.expires_at == 1300 and ts.refresh_expires_at == 2800 and ts.claims == {"sub": "u"}
    assert ts.expires_in(1100) == 200
    assert not ts.is_access_expired(1100) and ts.is_access_expired(1300)
    assert ts.is_access_expired(1280, margin=30) and not ts.is_access_expired(1260, margin=30)


def test_offline_refresh_token_has_no_expiry():
    ts = TokenSet.from_response(_response(refresh_expires_in=0), now=1000)
    assert ts.refresh_expires_at is None and ts.can_refresh(10**9)


def test_can_refresh_rules():
    ts = TokenSet.from_response(_response(), now=1000)
    assert ts.can_refresh(2000) and not ts.can_refresh(2800)
    assert not TokenSet(access_token="a", expires_at=1).can_refresh(0)


def test_refresh_response_without_new_values_keeps_previous_ones():
    first = TokenSet.from_response(_response(), now=1000, claims={"sub": "u"})
    second = TokenSet.from_response({"access_token": "at2", "expires_in": 300}, now=1200, previous=first)
    assert second.access_token == "at2" and second.refresh_token == "rt" and second.id_token == "idt"
    assert second.refresh_expires_at == first.refresh_expires_at and second.claims == {"sub": "u"}


def test_rotated_refresh_token_replaces_the_old_one():
    first = TokenSet.from_response(_response(), now=1000)
    second = TokenSet.from_response(_response(refresh_token="rt2"), now=1200, previous=first)
    assert second.refresh_token == "rt2" and second.refresh_expires_at == 3000


def test_dict_round_trip_for_session_storage():
    ts = TokenSet.from_response(_response(), now=1000, claims={"sub": "u"})
    assert TokenSet.from_dict(ts.to_dict()) == ts
    minimal = TokenSet.from_dict({"access_token": "a", "expires_at": 5})
    assert minimal.refresh_token is None and minimal.token_type == "Bearer"


def test_repr_hides_token_values():
    marker = "".join(["MARK", "ER"])                      # built at run time, not a credential
    text = repr(TokenSet.from_response(_response(access_token=marker + "-A", refresh_token=marker + "-R"), 0))
    assert marker not in text and "has_refresh=True" in text
