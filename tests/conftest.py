"""Shared test fixtures: make api/ and webapp/ importable and provide a throw-away RSA signing key."""
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
# Both services use top-level module names (api_app, api_auth, app, helpers).
for sub in ("api", "webapp"):
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
