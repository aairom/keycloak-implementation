"""OIDC discovery and signing-key (JWKS) cache, plus a small retrying HTTP helper.

Kept separate from the flow logic so that it can be reused for pure resource-server use cases
(validating bearer tokens only) and tested on its own.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

import jwt
import requests
from jwt import PyJWK

from .config import KeycloakConfig
from .errors import DiscoveryError, TokenValidationError

log = logging.getLogger("keycloak_connector")

# After an unknown ``kid`` the JWKS is refetched, but never more often than this (protects Keycloak from floods
# of forged tokens carrying random key ids).
MIN_JWKS_REFETCH_SECONDS = 10


class HttpClient:
    """``requests`` wrapper with timeout, TLS settings and exponential-backoff retries.

    Retries happen for connection problems and HTTP 5xx answers only. A 4xx answer is a definite
    answer of the server and is returned unchanged.
    """

    def __init__(self, config: KeycloakConfig, session: requests.Session | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self._config = config
        self._session = session or requests.Session()
        self._sleep = sleep

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Send a request; raises ``requests.RequestException`` once every attempt failed."""
        kwargs.setdefault("timeout", self._config.timeout)
        kwargs.setdefault("verify", self._config.verify)
        delay = self._config.backoff
        attempts = self._config.retries + 1
        for attempt in range(1, attempts + 1):
            try:
                response = self._session.request(method, url, **kwargs)
            except requests.RequestException as exc:
                if attempt == attempts:
                    raise
                log.warning("Keycloak request failed (%s), retry %d/%d", type(exc).__name__, attempt, attempts - 1)
            else:
                if response.status_code < 500 or attempt == attempts:
                    return response
                log.warning("Keycloak answered HTTP %d, retry %d/%d", response.status_code, attempt, attempts - 1)
            self._sleep(delay)
            delay *= 2
        raise AssertionError("unreachable")  # pragma: no cover


class KeyStore:
    """Caches the discovery document and the realm's signing keys, with TTL and kid-rotation handling."""

    def __init__(self, config: KeycloakConfig, http: HttpClient, clock: Callable[[], float] = time.time):
        self._config = config
        self._http = http
        self._clock = clock
        self._lock = threading.RLock()   # re-entrant: load_keys calls discovery() while holding it
        self._discovery: dict[str, Any] | None = None
        self._discovery_at = 0.0
        self._keys: dict[str, PyJWK] = {}
        self._keys_at = 0.0
        self._last_forced_refetch = 0.0

    # ------------------------------------------------------------------ discovery
    def discovery(self, force: bool = False) -> dict[str, Any]:
        """Return the (cached) discovery document after checking that it belongs to the configured realm."""
        with self._lock:
            fresh = self._discovery is not None and self._clock() - self._discovery_at < self._config.discovery_ttl
            if fresh and not force:
                return self._discovery  # type: ignore[return-value]
            doc = self._fetch_json(self._config.discovery_url, "discovery document")
            if doc.get("issuer") != self._config.issuer:
                raise DiscoveryError(
                    f"issuer mismatch: configured {self._config.issuer!r} but Keycloak announces "
                    f"{doc.get('issuer')!r} (check server_url, realm and Keycloak's hostname setting)")
            missing = [k for k in ("authorization_endpoint", "token_endpoint", "jwks_uri") if not doc.get(k)]
            if missing:
                raise DiscoveryError("discovery document lacks " + ", ".join(missing))
            self._discovery, self._discovery_at = doc, self._clock()
            return doc

    def endpoint(self, name: str) -> str:
        """URL of a discovery endpoint such as ``token_endpoint``; DiscoveryError if the server has none."""
        url = self.discovery().get(name)
        if not url:
            raise DiscoveryError(f"Keycloak does not publish {name}")
        return url

    # ------------------------------------------------------------------ signing keys
    def signing_key(self, token: str) -> PyJWK:
        """Return the public key that signed ``token`` (chosen by the ``kid`` header)."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenValidationError("token is not a well-formed JWT") from exc
        if header.get("alg") not in self._config.allowed_algs:
            raise TokenValidationError(f"token algorithm {header.get('alg')!r} is not allowed")
        kid = header.get("kid")
        self._ensure_keys()
        key = self._lookup(kid)
        if key is None and self._may_refetch():
            log.info("unknown signing key id, refreshing JWKS (key rotation?)")
            self._last_forced_refetch = self._clock()
            self.load_keys()
            key = self._lookup(kid)
        if key is None:
            raise TokenValidationError("no signing key matches the token's key id")
        return key

    def _lookup(self, kid: str | None) -> PyJWK | None:
        if kid is not None:
            return self._keys.get(kid)
        # Tokens without kid are accepted only when the realm publishes exactly one signing key.
        return next(iter(self._keys.values())) if len(self._keys) == 1 else None

    def _ensure_keys(self) -> None:
        if not self._keys or self._clock() - self._keys_at >= self._config.jwks_ttl:
            self.load_keys()

    def _may_refetch(self) -> bool:
        return self._clock() - self._last_forced_refetch >= MIN_JWKS_REFETCH_SECONDS

    def load_keys(self) -> None:
        with self._lock:
            data = self._fetch_json(self.endpoint("jwks_uri"), "JWKS")
            keys: dict[str, PyJWK] = {}
            for entry in data.get("keys", []):
                if entry.get("use") not in (None, "sig"):
                    continue          # skip encryption keys (RSA-OAEP ...)
                if entry.get("kty") not in ("RSA", "EC", "OKP"):
                    continue          # never accept symmetric keys from a JWKS (algorithm-confusion attacks)
                try:
                    jwk = PyJWK.from_dict(entry)
                except jwt.PyJWTError:
                    continue          # key type the library cannot use
                keys[entry.get("kid", "")] = jwk
            if not keys:
                raise DiscoveryError("JWKS contains no usable signing key")
            self._keys, self._keys_at = keys, self._clock()

    # ------------------------------------------------------------------ helper
    def _fetch_json(self, url: str, what: str) -> dict[str, Any]:
        try:
            response = self._http.request("GET", url)
        except requests.RequestException as exc:
            raise DiscoveryError(f"cannot reach Keycloak for the {what}: {type(exc).__name__}") from exc
        if response.status_code != 200:
            raise DiscoveryError(f"{what} request answered HTTP {response.status_code}")
        try:
            data = response.json()
        except ValueError as exc:
            raise DiscoveryError(f"{what} is not valid JSON") from exc
        if not isinstance(data, dict):
            raise DiscoveryError(f"{what} has an unexpected shape")
        return data
