"""Exception hierarchy of the Keycloak connector.

Every error derives from :class:`KeycloakConnectorError`, so callers can catch one type at the edge of
their application. Messages never contain tokens, codes or client secrets: they are safe to log.
"""
from __future__ import annotations


class KeycloakConnectorError(Exception):
    """Base class for every error raised by the connector."""


class ConfigError(KeycloakConnectorError):
    """The configuration is missing a value or contains an invalid one."""


class DiscoveryError(KeycloakConnectorError):
    """The OIDC discovery document or the JWKS could not be fetched or is unusable."""


class StateMismatchError(KeycloakConnectorError):
    """The ``state`` (or ``iss``) of the callback does not match the login request: possible CSRF."""


class AuthorizationError(KeycloakConnectorError):
    """Keycloak redirected back with an ``error`` parameter (user denied, login required ...)."""

    def __init__(self, error: str, description: str | None = None):
        self.error = error
        self.description = description
        super().__init__(f"authorization failed: {error}" + (f" ({description})" if description else ""))


class TokenError(KeycloakConnectorError):
    """The token endpoint (or userinfo endpoint) rejected the request or could not be reached."""

    def __init__(self, error: str, description: str | None = None, status: int | None = None):
        self.error = error
        self.description = description
        self.status = status
        parts = [f"token request failed: {error}"]
        if description:
            parts.append(f"({description})")
        if status:
            parts.append(f"[HTTP {status}]")
        super().__init__(" ".join(parts))


class TokenValidationError(KeycloakConnectorError):
    """A token failed signature, issuer, audience, expiry or nonce validation."""


class RefreshError(TokenError):
    """A refresh failed. ``reauth_required`` is True when the session is gone and the user must log in again."""

    def __init__(self, error: str, description: str | None = None, status: int | None = None,
                 reauth_required: bool = False):
        self.reauth_required = reauth_required
        super().__init__(error, description, status)
