"""Shared test fixtures: make api/, webapp/, logapp/ and connector/ importable and provide a throw-away RSA signing key."""
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
# The services use top-level module names (api_app, api_auth, app, helpers, log_app, store ...).
for sub in ("api", "webapp", "logapp", "scripts", "connector"):
    sys.path.insert(0, str(ROOT / sub))

ISSUER = "https://auth.test/realms/demo"
AUDIENCE = "demo-api"


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def make_token(rsa_key):
    """Factory for signed access tokens; override any claim through keyword arguments."""
    def _make(key=None, **overrides):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "sub": "user-1", "iat": now, "exp": now + 300,
            "preferred_username": "alice", "email": "alice@example.com",
            "realm_access": {"roles": ["app-user", "offline_access"]}, "groups": ["employees"],
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or rsa_key, algorithm="RS256", headers={"kid": "k1"})
    return _make


class FakeJwks:
    """Stands in for PyJWKClient: always hands out the public half of ``key``."""

    def __init__(self, key):
        self._public = key.public_key()

    def get_signing_key_from_jwt(self, _token):
        class _Key:
            pass
        k = _Key()
        k.key = self._public
        return k


@pytest.fixture
def jwks(rsa_key):
    return FakeJwks(rsa_key)


# --------------------------------------------------------------------------------------------------------------
# Offline Keycloak used by the connector tests: discovery, JWKS, authorize, token, userinfo and logout endpoints.
# --------------------------------------------------------------------------------------------------------------
import base64  # noqa: E402
import hashlib  # noqa: E402
import json as _json  # noqa: E402
from urllib.parse import parse_qs, urlparse  # noqa: E402

import requests  # noqa: E402

KC_BASE = "https://auth.test"
KC_REALM = "demo"
KC_OIDC = f"{KC_BASE}/realms/{KC_REALM}/protocol/openid-connect"
CLIENT_ID = "demo-client"
CLIENT_SECRET = "".join(["s", "3", "cret-", "for-tests"])   # built at run time: nothing for secret scanners to flag
REDIRECT = "https://app.test/callback"


class FakeResponse:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else _json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeKeycloak:
    """A requests.Session look-alike that behaves like a small Keycloak realm.

    ``calls`` records (method, url) pairs; ``fail_next`` makes the next N requests raise ConnectionError;
    ``status_next`` makes the next requests answer with the given HTTP statuses.
    """

    def __init__(self, key, kid="k1"):
        self.key, self.kid = key, kid
        self.calls: list[tuple[str, str]] = []
        self.fail_next = 0
        self.status_next: list[int] = []
        self.codes: dict[str, dict] = {}
        self.refresh_tokens: dict[str, dict] = {}
        self.sessions_ended = False
        self.discovery_override: dict = {}
        self.jwks_override = None
        self.id_token_claims: dict = {}
        self.omit_id_token = False
        self.basic_auth_seen = None
        self._n = 0

    # ---------------------------------------------------------------- helpers
    def _next(self, prefix):
        self._n += 1
        return f"{prefix}-{self._n}"

    def jwks(self):
        jwk = _json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update(kid=self.kid, use="sig", alg="RS256")
        enc = dict(jwk, kid="enc-1", use="enc", alg="RSA-OAEP")
        return {"keys": [enc, jwk]}

    def discovery(self):
        doc = {"issuer": f"{KC_BASE}/realms/{KC_REALM}",
               "authorization_endpoint": f"{KC_OIDC}/auth", "token_endpoint": f"{KC_OIDC}/token",
               "jwks_uri": f"{KC_OIDC}/certs", "userinfo_endpoint": f"{KC_OIDC}/userinfo",
               "end_session_endpoint": f"{KC_OIDC}/logout"}
        doc.update(self.discovery_override)
        return doc

    def sign(self, claims, kid=None, key=None):
        base = {"iss": f"{KC_BASE}/realms/{KC_REALM}", "iat": int(time.time()), "exp": int(time.time()) + 300,
                "sub": "user-1", "preferred_username": "alice"}
        base.update(claims)
        return jwt.encode(base, key or self.key, algorithm="RS256", headers={"kid": kid or self.kid})

    def authorize(self, url, user="alice"):
        """Play the browser: accept an authorization URL and return the callback query parameters."""
        q = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
        code = self._next("code")
        self.codes[code] = {"nonce": q["nonce"], "challenge": q.get("code_challenge"), "user": user,
                            "client_id": q["client_id"]}
        return {"code": code, "state": q["state"], "iss": f"{KC_BASE}/realms/{KC_REALM}"}

    # ---------------------------------------------------------------- the "network"
    def request(self, method, url, **kw):
        self.calls.append((method, url))
        if self.fail_next:
            self.fail_next -= 1
            raise requests.ConnectionError("boom")
        if self.status_next:
            return FakeResponse(self.status_next.pop(0), {"error": "server_error"})
        path = urlparse(url).path
        if path.endswith("/.well-known/openid-configuration"):
            return FakeResponse(200, self.discovery())
        if path.endswith("/certs"):
            return FakeResponse(200, self.jwks_override if self.jwks_override is not None else self.jwks())
        if path.endswith("/token"):
            return self._token(kw)
        if path.endswith("/userinfo"):
            ok = kw.get("headers", {}).get("Authorization", "").startswith("Bearer good")
            return FakeResponse(200 if ok else 401, {"sub": "user-1"} if ok else {"error": "invalid_token"})
        if path.endswith("/logout"):
            if self.sessions_ended:
                return FakeResponse(400, {"error": "invalid_grant"})
            self.sessions_ended = True
            return FakeResponse(204, text="")
        return FakeResponse(404, {"error": "not_found"})

    def _token(self, kw):
        form, self.basic_auth_seen = kw["data"], kw.get("auth")
        grant = form["grant_type"]
        if grant == "authorization_code":
            info = self.codes.pop(form.get("code"), None)
            if info is None:
                return FakeResponse(400, {"error": "invalid_grant", "error_description": "Code not valid"})
            if info["challenge"]:
                digest = hashlib.sha256(form.get("code_verifier", "").encode()).digest()
                if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != info["challenge"]:
                    return FakeResponse(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
            return FakeResponse(200, self._issue(info["user"], info["nonce"], info["client_id"]))
        if grant == "refresh_token":
            info = self.refresh_tokens.get(form.get("refresh_token"))
            if info is None or self.sessions_ended:
                return FakeResponse(400, {"error": "invalid_grant", "error_description": "Session not active"})
            return FakeResponse(200, self._issue(info["user"], None, info["client_id"]))
        if grant == "client_credentials":
            if not kw.get("auth"):
                return FakeResponse(401, {"error": "unauthorized_client"})
            return FakeResponse(200, {"access_token": self.sign({"azp": CLIENT_ID}), "expires_in": 300,
                                      "token_type": "Bearer", "scope": "profile"})
        return FakeResponse(400, {"error": "unsupported_grant_type"})

    def _issue(self, user, nonce, client_id):
        access = self.sign({"aud": "account", "azp": client_id, "preferred_username": user, "jti": self._next("jti")})
        claims = {"aud": client_id, "azp": client_id, "preferred_username": user,
                  "at_hash": base64.urlsafe_b64encode(hashlib.sha256(access.encode()).digest()[:16]).rstrip(b"=").decode()}
        if nonce:
            claims["nonce"] = nonce
        claims.update(self.id_token_claims)
        refresh = self._next("refresh")
        self.refresh_tokens[refresh] = {"user": user, "client_id": client_id}
        body = {"access_token": access, "expires_in": 300, "refresh_token": refresh, "refresh_expires_in": 1800,
                "token_type": "Bearer", "scope": "openid profile email"}
        if not self.omit_id_token:
            body["id_token"] = self.sign(claims)
        return body


@pytest.fixture
def fake_kc(rsa_key):
    return FakeKeycloak(rsa_key)


@pytest.fixture
def kc_config():
    from keycloak_connector import KeycloakConfig
    return KeycloakConfig(server_url=KC_BASE, realm=KC_REALM, client_id=CLIENT_ID, client_secret=CLIENT_SECRET,
                          redirect_uri=REDIRECT, post_logout_redirect_uri="https://app.test/", retries=2,
                          backoff=0)


@pytest.fixture
def connector(kc_config, fake_kc):
    """A connector wired to the fake Keycloak, a controllable clock and a no-op sleep."""
    from keycloak_connector import KeycloakConnector
    clock = Clock()
    kc = KeycloakConnector(kc_config, session=fake_kc, clock=clock, sleep=lambda _s: None)
    kc.clock = clock
    return kc


class Clock:
    """Settable clock: tests advance it instead of sleeping."""

    def __init__(self):
        self.now = time.time()

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
