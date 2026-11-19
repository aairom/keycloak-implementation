"""Plug-and-play Keycloak (OAuth2 / OpenID Connect) connector for web applications.

Public API::

    from keycloak_connector import KeycloakConfig, KeycloakConnector
"""
from .config import KeycloakConfig
from .connector import KeycloakConnector
from .errors import (AuthorizationError, ConfigError, DiscoveryError, KeycloakConnectorError, RefreshError,
                     StateMismatchError, TokenError, TokenValidationError)
from .tokens import LoginRequest, TokenSet

__version__ = "1.0.0"

__all__ = [
    "KeycloakConfig", "KeycloakConnector", "LoginRequest", "TokenSet", "KeycloakConnectorError", "ConfigError",
    "DiscoveryError", "StateMismatchError", "AuthorizationError", "TokenError", "TokenValidationError",
    "RefreshError", "__version__",
]
