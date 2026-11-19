"""Connector configuration: one validated, immutable object holding everything the connector needs."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlparse

from .errors import ConfigError

# Environment variable names read by KeycloakConfig.from_env (prefix configurable).
ENV_PREFIX = "KEYCLOAK_"


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


@dataclass(frozen=True)
class KeycloakConfig:
    """Settings of one Keycloak client (OIDC relying party).

    Required: ``server_url``, ``realm``, ``client_id``, ``redirect_uri``.
    ``client_secret`` is optional: leave it empty for a public client (PKCE protects the code flow).
    """

    server_url: str                      # base URL of Keycloak, e.g. https://auth.example.com (no /realms suffix)
    realm: str                           # realm name
    client_id: str
    redirect_uri: str                    # must be registered on the client in Keycloak
    client_secret: str | None = None     # confidential clients only; never logged
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    post_logout_redirect_uri: str | None = None
    audience: str | None = None          # expected ``aud`` of access tokens; None skips the audience check
    use_pkce: bool = True                # always recommended, also for confidential clients
    verify: bool | str = True            # True, False (never in production) or path of a CA bundle
    timeout: float = 10.0                # seconds per HTTP request
    retries: int = 2                     # extra attempts for network errors and 5xx answers
    backoff: float = 0.3                 # first retry delay in seconds, doubled each attempt
    leeway: int = 10                     # clock skew tolerated for exp/nbf/iat, in seconds
    refresh_margin: int = 30             # a token that expires within this many seconds counts as expired
    jwks_ttl: int = 300                  # seconds the signing keys are cached
    discovery_ttl: int = 3600            # seconds the discovery document is cached
    allowed_algs: tuple[str, ...] = ("RS256",)
    extra_params: Mapping[str, str] = field(default_factory=dict)  # extra authorization-request params

    def __post_init__(self) -> None:
        # Normalise first, then validate, so error messages point at the cleaned values.
        object.__setattr__(self, "server_url", (self.server_url or "").strip().rstrip("/"))
        object.__setattr__(self, "scopes", tuple(self.scopes))
        object.__setattr__(self, "allowed_algs", tuple(self.allowed_algs))
        if not self.client_secret:
            object.__setattr__(self, "client_secret", None)
        self.validate()

    # ------------------------------------------------------------------ validation
    def validate(self) -> None:
        """Raise :class:`ConfigError` listing every problem found (never includes the secret)."""
        problems: list[str] = []
        for name in ("server_url", "realm", "client_id", "redirect_uri"):
            if not str(getattr(self, name) or "").strip():
                problems.append(f"{name} is required")
        if self.server_url and not _is_http_url(self.server_url):
            problems.append("server_url must be an http(s) URL")
        if self.redirect_uri and not _is_http_url(self.redirect_uri):
            problems.append("redirect_uri must be an absolute http(s) URL")
        if self.post_logout_redirect_uri and not _is_http_url(self.post_logout_redirect_uri):
            problems.append("post_logout_redirect_uri must be an absolute http(s) URL")
        if "openid" not in self.scopes:
            problems.append("scopes must contain 'openid'")
        if self.timeout <= 0:
            problems.append("timeout must be positive")
        if self.retries < 0:
            problems.append("retries must be >= 0")
        if not self.allowed_algs or any(a.lower() == "none" for a in self.allowed_algs):
            problems.append("allowed_algs must be non-empty and must not contain 'none'")
        if problems:
            raise ConfigError("invalid Keycloak configuration: " + "; ".join(problems))

    # ------------------------------------------------------------------ derived values
    @property
    def issuer(self) -> str:
        """Expected ``iss`` of every token: ``<server_url>/realms/<realm>``."""
        return f"{self.server_url}/realms/{self.realm}"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def is_confidential(self) -> bool:
        return self.client_secret is not None

    def __repr__(self) -> str:  # the secret must never leak through logs or tracebacks
        secret = "set" if self.client_secret else "none"
        return (f"KeycloakConfig(server_url={self.server_url!r}, realm={self.realm!r}, "
                f"client_id={self.client_id!r}, redirect_uri={self.redirect_uri!r}, client_secret=<{secret}>)")

    # ------------------------------------------------------------------ construction helpers
    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, prefix: str = ENV_PREFIX) -> "KeycloakConfig":
        """Build the configuration from ``<PREFIX>SERVER_URL``, ``<PREFIX>REALM``, ``<PREFIX>CLIENT_ID``,
        ``<PREFIX>CLIENT_SECRET``, ``<PREFIX>REDIRECT_URI`` and the optional variables documented in the README."""
        env = os.environ if env is None else env

        def get(name: str, default: str | None = None) -> str | None:
            value = env.get(prefix + name)
            return value if value not in (None, "") else default

        def number(name: str, default, cast):
            raw = get(name)
            if raw is None:
                return default
            try:
                return cast(raw)
            except ValueError as exc:
                raise ConfigError(f"{prefix}{name} must be a number") from exc

        verify: bool | str = True
        ca_bundle = get("CA_BUNDLE")
        if ca_bundle:
            verify = ca_bundle
        elif not _bool(get("VERIFY_TLS"), True):
            verify = False

        scopes = tuple((get("SCOPES") or "openid profile email").replace(",", " ").split())
        return cls(
            server_url=get("SERVER_URL", "") or "",
            realm=get("REALM", "") or "",
            client_id=get("CLIENT_ID", "") or "",
            redirect_uri=get("REDIRECT_URI", "") or "",
            client_secret=get("CLIENT_SECRET"),
            scopes=scopes,
            post_logout_redirect_uri=get("POST_LOGOUT_REDIRECT_URI"),
            audience=get("AUDIENCE"),
            use_pkce=_bool(get("USE_PKCE"), True),
            verify=verify,
            timeout=number("TIMEOUT", 10.0, float),
            retries=number("RETRIES", 2, int),
            leeway=number("LEEWAY", 10, int),
            refresh_margin=number("REFRESH_MARGIN", 30, int),
            jwks_ttl=number("JWKS_TTL", 300, int),
        )
