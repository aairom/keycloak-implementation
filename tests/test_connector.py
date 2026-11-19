"""KeycloakConnector against the offline fake Keycloak: login, callback, validation, refresh, logout, errors."""
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from conftest import CLIENT_ID, KC_BASE, KC_OIDC, REDIRECT
from keycloak_connector import (AuthorizationError, DiscoveryError, KeycloakConfig, KeycloakConnector, LoginRequest,
                                RefreshError, StateMismatchError, TokenError, TokenSet, TokenValidationError)


def query(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def log_in(connector, fake_kc, **kw):
    login = connector.login_request(**kw)
    return login, connector.handle_callback(fake_kc.authorize(login.url), login)


# ---------------------------------------------------------------- initialisation
def test_initialize_warms_caches_and_returns_self(connector, fake_kc):
    assert connector.initialize() is connector
    assert any(u.endswith("/certs") for _, u in fake_kc.calls)


def test_initialize_fails_fast_on_wrong_issuer(connector, fake_kc):
    fake_kc.discovery_override = {"issuer": "https://other.test/realms/demo"}
    with pytest.raises(DiscoveryError):
        connector.initialize()


def test_health_reports_without_raising(connector, fake_kc):
    assert connector.health() is True
    fake_kc.fail_next = 10
    assert connector.health() is False


# ---------------------------------------------------------------- login request
def test_login_request_carries_oidc_and_pkce_parameters(connector):
    login = connector.login_request()
    q = query(login.url)
    assert login.url.startswith(f"{KC_OIDC}/auth?")
    assert q["client_id"] == CLIENT_ID and q["response_type"] == "code" and q["redirect_uri"] == REDIRECT
    assert q["scope"] == "openid profile email" and q["state"] == login.state and q["nonce"] == login.nonce
    assert q["code_challenge_method"] == "S256" and login.code_verifier and "code_verifier" not in q


def test_login_requests_are_unique(connector):
    a, b = connector.login_request(), connector.login_request()
    assert (a.state, a.nonce, a.code_verifier) != (b.state, b.nonce, b.code_verifier)


def test_login_options_override_and_extend(kc_config, fake_kc):
    cfg = KeycloakConfig(**{**kc_config.__dict__, "extra_params": {"kc_idp_hint": "github"}, "use_pkce": False})
    kc = KeycloakConnector(cfg, session=fake_kc)
    login = kc.login_request(login_hint="alice", prompt="login", scopes=("openid",), extra_params={"ui_locales": "de"})
    q = query(login.url)
    assert q["login_hint"] == "alice" and q["prompt"] == "login" and q["scope"] == "openid"
    assert q["kc_idp_hint"] == "github" and q["ui_locales"] == "de"
    assert "code_challenge" not in q and login.code_verifier is None


# ---------------------------------------------------------------- full flow
def test_full_authorization_code_flow(connector, fake_kc):
    login, tokens = log_in(connector, fake_kc)
    assert tokens.claims["preferred_username"] == "alice" and tokens.claims["aud"] == CLIENT_ID
    assert tokens.refresh_token and tokens.id_token and tokens.can_refresh(connector.clock())
    assert fake_kc.basic_auth_seen == (CLIENT_ID, connector.config.client_secret)     # confidential: Basic auth
    assert connector.validate_access_token(tokens.access_token)["preferred_username"] == "alice"


def test_callback_accepts_session_dict(connector, fake_kc):
    login = connector.login_request()
    tokens = connector.handle_callback(fake_kc.authorize(login.url), login.to_session())
    assert tokens.access_token


def test_public_client_sends_client_id_without_secret(kc_config, fake_kc):
    cfg = KeycloakConfig(**{**kc_config.__dict__, "client_secret": None})
    kc = KeycloakConnector(cfg, session=fake_kc, sleep=lambda _s: None)
    login = kc.login_request()
    kc.handle_callback(fake_kc.authorize(login.url), login)
    assert fake_kc.basic_auth_seen is None


# ---------------------------------------------------------------- callback errors
def test_callback_error_parameter(connector):
    login = connector.login_request()
    with pytest.raises(AuthorizationError) as info:
        connector.handle_callback({"error": "access_denied", "error_description": "no", "state": login.state}, login)
    assert info.value.error == "access_denied"


@pytest.mark.parametrize("state", ["", "tampered"])
def test_callback_state_mismatch(connector, fake_kc, state):
    login = connector.login_request()
    params = {**fake_kc.authorize(login.url), "state": state}
    with pytest.raises(StateMismatchError):
        connector.handle_callback(params, login)


def test_callback_issuer_mix_up_rejected(connector, fake_kc):
    login = connector.login_request()
    params = {**fake_kc.authorize(login.url), "iss": "https://evil.test/realms/demo"}
    with pytest.raises(StateMismatchError, match="issuer"):
        connector.handle_callback(params, login)


def test_callback_without_code(connector):
    login = connector.login_request()
    with pytest.raises(AuthorizationError, match="invalid_response"):
        connector.handle_callback({"state": login.state}, login)


def test_authorization_code_is_single_use(connector, fake_kc):
    login = connector.login_request()
    params = fake_kc.authorize(login.url)
    connector.handle_callback(params, login)
    with pytest.raises(TokenError) as info:
        connector.handle_callback(params, login)
    assert info.value.error == "invalid_grant" and info.value.status == 400


def test_wrong_pkce_verifier_rejected_by_keycloak(connector, fake_kc):
    login = connector.login_request()
    params = fake_kc.authorize(login.url)
    forged = LoginRequest(url="", state=login.state, nonce=login.nonce, code_verifier="x" * 64)
    with pytest.raises(TokenError, match="PKCE"):
        connector.handle_callback(params, forged)


def test_nonce_mismatch_rejected(connector, fake_kc):
    login = connector.login_request()
    params = fake_kc.authorize(login.url)
    other = LoginRequest(url="", state=login.state, nonce="different", code_verifier=login.code_verifier)
    with pytest.raises(TokenValidationError, match="nonce"):
        connector.handle_callback(params, other)


def test_missing_id_token_rejected(connector, fake_kc):
    fake_kc.omit_id_token = True
    login = connector.login_request()
    with pytest.raises(TokenValidationError, match="id_token"):
        connector.handle_callback(fake_kc.authorize(login.url), login)


def test_id_token_for_another_client_rejected(connector, fake_kc):
    fake_kc.id_token_claims = {"aud": "someone-else"}
    login = connector.login_request()
    with pytest.raises(TokenValidationError, match="audience"):
        connector.handle_callback(fake_kc.authorize(login.url), login)


def test_at_hash_mismatch_rejected(connector, fake_kc):
    fake_kc.id_token_claims = {"at_hash": "AAAAAAAAAAAAAAAAAAAAAA"}
    login = connector.login_request()
    with pytest.raises(TokenValidationError, match="at_hash"):
        connector.handle_callback(fake_kc.authorize(login.url), login)


# ---------------------------------------------------------------- token validation
def test_expired_token_rejected_but_leeway_applies(connector, fake_kc):
    with pytest.raises(TokenValidationError, match="expired"):
        connector.validate_access_token(fake_kc.sign({"exp": int(connector.clock()) - 3600}))
    assert connector.validate_access_token(fake_kc.sign({"exp": int(connector.clock()) - 5}))   # inside 10 s leeway


def test_wrong_issuer_rejected(connector, fake_kc):
    with pytest.raises(TokenValidationError, match="issuer"):
        connector.validate_access_token(fake_kc.sign({"iss": "https://evil.test/realms/demo"}))


def test_token_signed_by_unknown_key_rejected(connector, fake_kc, other_rsa_key):
    with pytest.raises(TokenValidationError):
        connector.validate_access_token(fake_kc.sign({}, key=other_rsa_key))      # right kid, wrong key


def test_audience_checked_only_when_configured(connector, fake_kc):
    token = fake_kc.sign({"aud": "account"})
    assert connector.validate_access_token(token)
    assert connector.validate_access_token(token, audience="account")
    with pytest.raises(TokenValidationError, match="audience"):
        connector.validate_access_token(token, audience="demo-api")
    connector.config = KeycloakConfig(**{**connector.config.__dict__, "audience": "demo-api"})
    with pytest.raises(TokenValidationError):
        connector.validate_access_token(token)


def test_garbage_and_unsigned_tokens_rejected(connector, fake_kc):
    with pytest.raises(TokenValidationError):
        connector.validate_access_token("garbage")
    import jwt
    unsigned = jwt.encode({"iss": connector.config.issuer, "exp": 9999999999}, None, algorithm="none")
    with pytest.raises(TokenValidationError):
        connector.validate_access_token(unsigned)


def test_token_without_exp_rejected(connector, fake_kc):
    import jwt
    token = jwt.encode({"iss": connector.config.issuer}, fake_kc.key, algorithm="RS256", headers={"kid": "k1"})
    with pytest.raises(TokenValidationError):
        connector.validate_access_token(token)


def test_key_rotation_is_transparent(connector, fake_kc, other_rsa_key):
    _, tokens = log_in(connector, fake_kc)
    fake_kc.key, fake_kc.kid = other_rsa_key, "k2"
    assert connector.validate_access_token(fake_kc.sign({"aud": "account"}))["sub"] == "user-1"
    assert tokens


# ---------------------------------------------------------------- refresh
def test_refresh_returns_new_tokens_and_keeps_claims(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    connector.clock.advance(100)
    fresh = connector.refresh(tokens)
    assert fresh.access_token != tokens.access_token and fresh.expires_at > tokens.expires_at
    assert fresh.claims["preferred_username"] == "alice"


def test_refresh_accepts_a_raw_refresh_token(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    assert connector.refresh(tokens.refresh_token).access_token


def test_refresh_without_refresh_token(connector):
    with pytest.raises(RefreshError) as info:
        connector.refresh(TokenSet(access_token="a", expires_at=1))
    assert info.value.reauth_required


def test_refresh_after_session_ended_requires_reauthentication(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    fake_kc.sessions_ended = True
    with pytest.raises(RefreshError) as info:
        connector.refresh(tokens)
    assert info.value.reauth_required and info.value.error == "invalid_grant"


def test_refresh_survives_a_transient_outage(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    fake_kc.fail_next = 2                                    # two failures, third attempt works
    assert connector.refresh(tokens).access_token


def test_refresh_outage_is_not_a_reauth_request(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    fake_kc.fail_next = 10
    with pytest.raises(RefreshError) as info:
        connector.refresh(tokens)
    assert info.value.error == "connection_error" and not info.value.reauth_required


def test_ensure_fresh_leaves_valid_tokens_alone_and_refreshes_expiring_ones(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    assert connector.ensure_fresh(tokens) is tokens
    connector.clock.advance(280)                             # inside the 30 s refresh margin
    renewed = connector.ensure_fresh(tokens)
    assert renewed is not tokens and renewed.expires_at > tokens.expires_at


def test_ensure_fresh_when_everything_expired(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    connector.clock.advance(5000)
    with pytest.raises(RefreshError) as info:
        connector.ensure_fresh(tokens)
    assert info.value.error == "session_expired" and info.value.reauth_required


# ---------------------------------------------------------------- logout
def test_logout_url_with_tokens_and_overrides(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    q = query(connector.logout_url(tokens, state="s1"))
    assert q["id_token_hint"] == tokens.id_token and q["client_id"] == CLIENT_ID
    assert q["post_logout_redirect_uri"] == "https://app.test/" and q["state"] == "s1"
    assert query(connector.logout_url(tokens.id_token, "https://app.test/bye"))["post_logout_redirect_uri"].endswith("/bye")


def test_logout_url_without_hint_or_target(kc_config, fake_kc):
    kc = KeycloakConnector(KeycloakConfig(**{**kc_config.__dict__, "post_logout_redirect_uri": None}), session=fake_kc)
    q = query(kc.logout_url())
    assert q == {"client_id": CLIENT_ID}


def test_backchannel_logout_ends_the_session(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    assert connector.logout_backchannel(tokens) is True
    with pytest.raises(RefreshError):                        # the session is gone, refresh no longer works
        connector.refresh(tokens)
    assert connector.logout_backchannel(tokens.refresh_token) is False       # second attempt: already ended
    assert connector.logout_backchannel(TokenSet(access_token="a", expires_at=1)) is False


def test_backchannel_logout_network_error(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    fake_kc.fail_next = 10
    with pytest.raises(TokenError, match="connection_error"):
        connector.logout_backchannel(tokens)


# ---------------------------------------------------------------- client credentials and userinfo
def test_client_credentials(connector, fake_kc):
    tokens = connector.client_credentials(scopes=("profile",))
    assert tokens.access_token and tokens.refresh_token is None
    assert connector.validate_access_token(tokens.access_token)["azp"] == CLIENT_ID


def test_client_credentials_needs_a_secret(kc_config, fake_kc):
    kc = KeycloakConnector(KeycloakConfig(**{**kc_config.__dict__, "client_secret": None}), session=fake_kc)
    with pytest.raises(TokenError, match="unauthorized_client"):
        kc.client_credentials()


def test_userinfo(connector, fake_kc):
    assert connector.userinfo("good-token")["sub"] == "user-1"
    assert connector.userinfo(TokenSet(access_token="good-1", expires_at=1))["sub"] == "user-1"
    with pytest.raises(TokenError, match="rejected") as info:
        connector.userinfo("bad")
    assert info.value.status == 401


def test_userinfo_other_failure_and_network_error(connector, fake_kc):
    connector.initialize()
    fake_kc.status_next = [403]
    with pytest.raises(TokenError, match="userinfo_failed"):
        connector.userinfo("x")
    fake_kc.fail_next = 10
    with pytest.raises(TokenError, match="connection_error"):
        connector.userinfo("x")


# ---------------------------------------------------------------- token endpoint failure modes
def test_token_endpoint_server_error_and_non_json(connector, fake_kc):
    login = connector.login_request()
    params = fake_kc.authorize(login.url)
    fake_kc.status_next = [500, 500, 500]
    with pytest.raises(TokenError) as info:
        connector.handle_callback(params, login)
    assert info.value.status == 500 and info.value.error == "server_error"


def test_token_response_without_access_token(connector, fake_kc, monkeypatch):
    from conftest import FakeResponse
    original = fake_kc.request
    monkeypatch.setattr(fake_kc, "request", lambda m, u, **kw: FakeResponse(200, {"foo": 1}) if u.endswith("/token") else original(m, u, **kw))
    with pytest.raises(TokenError, match="invalid_response"):
        connector.client_credentials()


def test_token_endpoint_unreachable_message_has_no_secret(connector, fake_kc):
    login = connector.login_request()          # also loads the discovery document
    fake_kc.fail_next = 10
    with pytest.raises(TokenError) as info:
        connector.exchange_code("c", login)
    assert connector.config.client_secret not in str(info.value)


def test_exchange_code_accepts_session_dict(connector, fake_kc):
    login = connector.login_request()
    code = fake_kc.authorize(login.url)["code"]
    assert connector.exchange_code(code, login.to_session()).access_token


def test_non_json_error_body_still_yields_token_error(connector, fake_kc, monkeypatch):
    from conftest import FakeResponse
    original = fake_kc.request
    monkeypatch.setattr(fake_kc, "request", lambda m, u, **kw: FakeResponse(502, None, text="<html>Bad gateway</html>") if u.endswith("/token") else original(m, u, **kw))
    login = connector.login_request()
    with pytest.raises(TokenError) as info:
        connector.exchange_code("c", login)
    assert info.value.status == 502 and info.value.error == "server_error"


def test_code_flow_without_pkce_sends_no_verifier(kc_config, fake_kc):
    kc = KeycloakConnector(KeycloakConfig(**{**kc_config.__dict__, "use_pkce": False}), session=fake_kc, sleep=lambda _s: None)
    login = kc.login_request()
    assert kc.handle_callback(fake_kc.authorize(login.url), login).access_token


def test_refresh_with_id_token_updates_claims_and_validates_it(connector, fake_kc):
    _, tokens = log_in(connector, fake_kc)
    fake_kc.id_token_claims = {"aud": "intruder"}
    with pytest.raises(TokenValidationError):
        connector.refresh(tokens)
