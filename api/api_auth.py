"""Token validation and Keycloak Authorization Services client for the demo API.

Two responsibilities:
* ``TokenValidator``  - verifies RS256 access tokens (signature via JWKS, issuer, audience, expiry).
* ``PolicyDecisionClient`` - asks Keycloak (UMA ticket grant, ``response_mode=decision``) whether the
  caller may use a given resource/scope, so policies live in Keycloak and not in the API code.
"""
from __future__ import annotations

import jwt
import requests
from jwt import PyJWKClient

UMA_GRANT = "urn:ietf:params:oauth:grant-type:uma-ticket"


class AuthError(Exception):
    """Raised when a token is missing, malformed or invalid (maps to HTTP 401)."""


def discover(discovery_url: str, timeout: float = 5.0) -> dict:
    """Fetch the OpenID Connect discovery document."""
    resp = requests.get(discovery_url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def extract_bearer(authorization_header: str | None) -> str:
    """Return the token from an ``Authorization: Bearer <token>`` header."""
    if not authorization_header:
        raise AuthError("missing Authorization header")
    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError("Authorization header must be 'Bearer <token>'")
    return token.strip()


class TokenValidator:
    """Validate Keycloak access tokens against the realm's published signing keys."""

    def __init__(self, issuer: str, audience: str, jwks_uri: str | None = None,
                 jwks_client: PyJWKClient | None = None, leeway: int = 10):
        if jwks_client is None and not jwks_uri:
            raise ValueError("either jwks_uri or jwks_client is required")
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway
        self._jwks = jwks_client or PyJWKClient(jwks_uri, cache_keys=True)

    def validate(self, token: str) -> dict:
        """Return the verified claims or raise ``AuthError``."""
        try:
            key = self._jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(
                token,
                key,
                algorithms=["RS256", "ES256", "PS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"invalid token: {exc}") from exc


class PolicyDecisionClient:
    """Ask Keycloak's policy decision point whether ``resource#scope`` is permitted."""

    def __init__(self, token_endpoint: str, audience: str, timeout: float = 5.0):
        self.token_endpoint = token_endpoint
        self.audience = audience
        self.timeout = timeout

    def is_permitted(self, access_token: str, resource: str, scope: str) -> bool:
        resp = requests.post(
            self.token_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            data={
                "grant_type": UMA_GRANT,
                "audience": self.audience,
                "permission": f"{resource}#{scope}",
                "response_mode": "decision",
            },
            timeout=self.timeout,
        )
        if resp.status_code == 200:
            return bool(resp.json().get("result"))
        if resp.status_code in (401, 403):
            return False
        resp.raise_for_status()
        return False
