"""HttpClient retries and KeyStore: discovery validation, JWKS cache, kid rotation."""
import jwt
import pytest
import requests

from conftest import KC_OIDC, FakeResponse
from keycloak_connector import DiscoveryError, KeycloakConfig, TokenValidationError
from keycloak_connector.discovery import HttpClient, KeyStore


@pytest.fixture
def cfg(kc_config):
    return kc_config


def make_store(cfg, fake, clock):
    return KeyStore(cfg, HttpClient(cfg, fake, sleep=lambda _s: None), clock)


# ---------------------------------------------------------------- HttpClient
def test_http_client_retries_connection_errors_then_succeeds(cfg, fake_kc):
    sleeps = []
    http = HttpClient(KeycloakConfig(**{**cfg.__dict__, "backoff": 0.5}), fake_kc, sleep=sleeps.append)
    fake_kc.fail_next = 2
    assert http.request("GET", cfg.discovery_url).status_code == 200
    assert sleeps == [0.5, 1.0]                       # exponential backoff


def test_http_client_gives_up_after_all_attempts(cfg, fake_kc):
    http = HttpClient(cfg, fake_kc, sleep=lambda _s: None)
    fake_kc.fail_next = 10
    with pytest.raises(requests.ConnectionError):
        http.request("GET", cfg.discovery_url)
    assert len(fake_kc.calls) == cfg.retries + 1


def test_http_client_retries_5xx_but_not_4xx(cfg, fake_kc):
    http = HttpClient(cfg, fake_kc, sleep=lambda _s: None)
    fake_kc.status_next = [503, 502]
    assert http.request("GET", cfg.discovery_url).status_code == 200
    fake_kc.calls.clear()
    assert http.request("GET", f"{KC_OIDC}/nothing").status_code == 404
    assert len(fake_kc.calls) == 1


def test_http_client_returns_last_5xx_when_exhausted(cfg, fake_kc):
    http = HttpClient(cfg, fake_kc, sleep=lambda _s: None)
    fake_kc.status_next = [500, 500, 500]
    assert http.request("GET", cfg.discovery_url).status_code == 500


def test_http_client_passes_timeout_and_tls_settings(cfg):
    seen = {}

    class Spy:
        def request(self, method, url, **kw):
            seen.update(kw)
            return FakeResponse(200, {})
    HttpClient(KeycloakConfig(**{**cfg.__dict__, "verify": "/ca.pem", "timeout": 4}), Spy()).request("GET", "https://x.test")
    assert seen["timeout"] == 4 and seen["verify"] == "/ca.pem"


def test_http_client_builds_its_own_session_by_default(cfg):
    assert isinstance(HttpClient(cfg)._session, requests.Session)


# ---------------------------------------------------------------- discovery
def test_discovery_is_cached_until_ttl(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    store.discovery(); store.discovery()
    assert len(fake_kc.calls) == 1
    connector.clock.advance(cfg.discovery_ttl + 1)
    store.discovery()
    assert len(fake_kc.calls) == 2
    store.discovery(force=True)
    assert len(fake_kc.calls) == 3


def test_discovery_rejects_wrong_issuer(cfg, fake_kc, connector):
    fake_kc.discovery_override = {"issuer": "https://evil.test/realms/demo"}
    with pytest.raises(DiscoveryError, match="issuer mismatch"):
        make_store(cfg, fake_kc, connector.clock).discovery()


def test_discovery_rejects_missing_endpoints(cfg, fake_kc, connector):
    fake_kc.discovery_override = {"jwks_uri": ""}
    with pytest.raises(DiscoveryError, match="jwks_uri"):
        make_store(cfg, fake_kc, connector.clock).discovery()


def test_endpoint_lookup_and_missing_optional_endpoint(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    assert store.endpoint("token_endpoint").endswith("/token")
    fake_kc.discovery_override = {"userinfo_endpoint": None}
    store.discovery(force=True)
    with pytest.raises(DiscoveryError, match="userinfo_endpoint"):
        store.endpoint("userinfo_endpoint")


@pytest.mark.parametrize("behaviour,message", [
    ("down", "cannot reach"), ("status", "HTTP 404"), ("notjson", "not valid JSON"), ("list", "unexpected shape")])
def test_discovery_failure_modes(cfg, connector, behaviour, message):
    class Broken:
        def request(self, method, url, **kw):
            if behaviour == "down":
                raise requests.ConnectionError()
            return {"status": FakeResponse(404, {}), "notjson": FakeResponse(200, None, text="<html>"),
                    "list": FakeResponse(200, [1])}[behaviour]
    with pytest.raises(DiscoveryError, match=message):
        make_store(cfg, Broken(), connector.clock).discovery()


# ---------------------------------------------------------------- signing keys
def test_signing_key_found_and_encryption_key_skipped(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    key = store.signing_key(fake_kc.sign({"aud": "x"}))
    assert key.key_id == "k1"
    assert "enc-1" not in store._keys


def test_keys_cached_and_reloaded_after_ttl(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    token = fake_kc.sign({})
    store.signing_key(token); store.signing_key(token)
    certs = lambda: sum(1 for _, u in fake_kc.calls if u.endswith("/certs"))
    assert certs() == 1
    connector.clock.advance(cfg.jwks_ttl + 1)
    store.signing_key(token)
    assert certs() == 2


def test_unknown_kid_triggers_one_refetch_for_key_rotation(cfg, fake_kc, connector, other_rsa_key):
    store = make_store(cfg, fake_kc, connector.clock)
    store.signing_key(fake_kc.sign({}))
    fake_kc.key, fake_kc.kid = other_rsa_key, "k2"            # realm rotated its key
    assert store.signing_key(fake_kc.sign({})).key_id == "k2"


def test_unknown_kid_refetch_is_rate_limited(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    store.signing_key(fake_kc.sign({}))
    bad = fake_kc.sign({}, kid="forged")
    for _ in range(3):
        with pytest.raises(TokenValidationError, match="no signing key"):
            store.signing_key(bad)
    assert sum(1 for _, u in fake_kc.calls if u.endswith("/certs")) <= 2
    connector.clock.advance(11)                                # window passed: one more refetch allowed
    with pytest.raises(TokenValidationError):
        store.signing_key(bad)
    assert sum(1 for _, u in fake_kc.calls if u.endswith("/certs")) <= 3


def test_token_without_kid_accepted_only_with_single_key(cfg, fake_kc, connector):
    fake_kc.jwks_override = {"keys": [fake_kc.jwks()["keys"][1]]}
    store = make_store(cfg, fake_kc, connector.clock)
    no_kid = jwt.encode({"iss": cfg.issuer}, fake_kc.key, algorithm="RS256")
    assert store.signing_key(no_kid).key_id == "k1"
    fake_kc.jwks_override = {"keys": [dict(fake_kc.jwks()["keys"][1], kid="a"), dict(fake_kc.jwks()["keys"][1], kid="b")]}
    store2 = make_store(cfg, fake_kc, connector.clock)
    with pytest.raises(TokenValidationError):
        store2.signing_key(no_kid)


def test_disallowed_algorithm_and_garbage_rejected(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    hs = jwt.encode({"a": 1}, "k" * 32, algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(TokenValidationError, match="not allowed"):
        store.signing_key(hs)
    with pytest.raises(TokenValidationError, match="well-formed"):
        store.signing_key("not-a-jwt")


def test_jwks_without_usable_keys(cfg, fake_kc, connector):
    store = make_store(cfg, fake_kc, connector.clock)
    fake_kc.jwks_override = {"keys": [{"kty": "oct", "use": "sig", "kid": "z", "k": "AAAA"}, {"kty": "RSA", "use": "enc"}]}
    with pytest.raises(DiscoveryError, match="no usable signing key"):
        store.load_keys()


def test_unusable_key_types_are_skipped(cfg, fake_kc, connector):
    good = fake_kc.jwks()["keys"][1]
    broken = {"kty": "RSA", "use": "sig", "kid": "broken", "n": "!", "e": "AQAB"}
    fake_kc.jwks_override = {"keys": [broken, good]}
    store = make_store(cfg, fake_kc, connector.clock)
    store.load_keys()
    assert set(store._keys) == {"k1"}
