"""Unit tests for api/api_auth.py (token validation and the policy decision client)."""
import time
from unittest import mock

import jwt
import pytest

from api_auth import (AuthError, PolicyDecisionClient, TokenValidator, discover, extract_bearer,
                      UMA_GRANT)
from conftest import AUDIENCE, ISSUER


@pytest.fixture
def validator(jwks):
    return TokenValidator(ISSUER, AUDIENCE, jwks_client=jwks)


def test_valid_token_returns_claims(validator, make_token):
    claims = validator.validate(make_token())
    assert claims["preferred_username"] == "alice"


def test_expired_token_rejected(validator, make_token):
    with pytest.raises(AuthError, match="invalid token"):
        validator.validate(make_token(exp=int(time.time()) - 3600))


def test_wrong_issuer_rejected(validator, make_token):
    with pytest.raises(AuthError):
        validator.validate(make_token(iss="https://evil.test/realms/demo"))


def test_wrong_audience_rejected(validator, make_token):
    with pytest.raises(AuthError):
        validator.validate(make_token(aud="some-other-api"))


def test_missing_required_claim_rejected(validator, make_token):
    with pytest.raises(AuthError):
        validator.validate(make_token(sub=None))


def test_token_signed_with_foreign_key_rejected(validator, make_token, other_rsa_key):
    with pytest.raises(AuthError):
        validator.validate(make_token(key=other_rsa_key))


def test_unsigned_alg_none_token_rejected(validator):
    forged = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": 1, "exp": 9999999999},
                        key=None, algorithm="none")
    with pytest.raises(AuthError):
        validator.validate(forged)


def test_garbage_token_rejected(validator):
    with pytest.raises(AuthError):
        validator.validate("not-a-jwt")


def test_validator_needs_a_key_source():
    with pytest.raises(ValueError):
        TokenValidator(ISSUER, AUDIENCE)


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer", "Bearer    "])
def test_extract_bearer_rejects_bad_headers(header):
    with pytest.raises(AuthError):
        extract_bearer(header)


def test_extract_bearer_accepts_case_insensitive_scheme():
    assert extract_bearer("bearer  tok123 ") == "tok123"


def _response(status, payload=None):
    resp = mock.Mock(status_code=status)
    resp.json.return_value = payload or {}
    resp.raise_for_status.side_effect = None if status < 400 else RuntimeError("boom")
    return resp


def test_pdp_permits_and_sends_uma_request():
    pdp = PolicyDecisionClient("https://kc/token", "demo-api")
    with mock.patch("api_auth.requests.post", return_value=_response(200, {"result": True})) as post:
        assert pdp.is_permitted("tok", "reports", "read") is True
    kwargs = post.call_args.kwargs
    assert kwargs["headers"]["Authorization"] == "Bearer tok"
    assert kwargs["data"] == {"grant_type": UMA_GRANT, "audience": "demo-api",
                              "permission": "reports#read", "response_mode": "decision"}


@pytest.mark.parametrize("status", [401, 403])
def test_pdp_denies_on_auth_failures(status):
    pdp = PolicyDecisionClient("https://kc/token", "demo-api")
    with mock.patch("api_auth.requests.post", return_value=_response(status)):
        assert pdp.is_permitted("tok", "reports", "write") is False


def test_pdp_denies_when_result_false():
    pdp = PolicyDecisionClient("https://kc/token", "demo-api")
    with mock.patch("api_auth.requests.post", return_value=_response(200, {"result": False})):
        assert pdp.is_permitted("tok", "admin-panel", "access") is False


def test_pdp_propagates_server_errors():
    pdp = PolicyDecisionClient("https://kc/token", "demo-api")
    with mock.patch("api_auth.requests.post", return_value=_response(500)):
        with pytest.raises(RuntimeError):
            pdp.is_permitted("tok", "reports", "read")


def test_discover_returns_document():
    with mock.patch("api_auth.requests.get", return_value=_response(200, {"jwks_uri": "x"})):
        assert discover("https://kc/.well-known/openid-configuration") == {"jwks_uri": "x"}
