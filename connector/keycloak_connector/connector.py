"""The Keycloak connector: initialise, log in, validate, refresh and log out through standard OAuth2/OIDC.

Framework-agnostic: the application owns the HTTP session and the redirects; the connector only builds URLs,
talks to Keycloak and validates tokens. Typical use::

    kc = KeycloakConnector(KeycloakConfig.from_env()).initialize()
    login = kc.login_request()                  # 1. keep login.to_session() server side, redirect to login.url
    tokens = kc.handle_callback(request.args, login)   # 2. on the redirect URI
    tokens = kc.ensure_fresh(tokens)            # 3. before each API call
    return redirect(kc.logout_url(tokens))      # 4. sign out
"""
from __future__ import annotations

import hmac
import logging
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

import jwt
import requests

from .config import KeycloakConfig
from .discovery import HttpClient, KeyStore
from .errors import (AuthorizationError, DiscoveryError, RefreshError, StateMismatchError, TokenError,
                     TokenValidationError)
from .pkce import challenge_s256, generate_verifier, half_hash, random_token
from .tokens import LoginRequest, TokenSet

log = logging.getLogger("keycloak_connector")


class KeycloakConnector:
    """One instance per Keycloak client; thread-safe after :meth:`initialize` (caches are lock protected)."""

    def __init__(self, config: KeycloakConfig, session: requests.Session | None = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        """``session``, ``clock`` and ``sleep`` can be injected, which is how the unit tests run without Keycloak."""
        self.config = config
        self._clock = clock
        self._http = HttpClient(config, session, sleep)
        self._keys = KeyStore(config, self._http, clock)

    # ================================================================== 1. initialisation
    def initialize(self) -> "KeycloakConnector":
        """Fetch discovery document and signing keys now, so misconfiguration fails at start-up.

        Raises :class:`DiscoveryError` when Keycloak is unreachable, the realm is wrong or the issuer differs
        from ``server_url`` (a classic reverse-proxy / hostname problem). Returns ``self`` for chaining.
        """
        self._keys.discovery(force=True)
        self._keys.load_keys()   # warm the key cache
        log.info("Keycloak connector ready for realm %s, client %s", self.config.realm, self.config.client_id)
        return self

    def health(self) -> bool:
        """True when Keycloak answers the discovery request correctly (for readiness probes); never raises."""
        try:
            self._keys.discovery(force=True)
            return True
        except DiscoveryError:
            return False

    # ================================================================== 2. login
    def login_request(self, *, login_hint: str | None = None, prompt: str | None = None,
                      scopes: tuple[str, ...] | None = None, extra_params: Mapping[str, str] | None = None
                      ) -> LoginRequest:
        """Build the authorization URL (code flow, S256 PKCE, state and nonce) for a browser redirect.

        Store ``result.to_session()`` in the user's server-side session; it is needed by :meth:`handle_callback`.
        ``prompt="login"`` forces re-authentication, ``prompt="none"`` checks for an existing SSO session silently.
        """
        state, nonce = random_token(), random_token()
        verifier = generate_verifier() if self.config.use_pkce else None
        params: dict[str, str] = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(scopes or self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        if verifier:
            params.update(code_challenge=challenge_s256(verifier), code_challenge_method="S256")
        if login_hint:
            params["login_hint"] = login_hint
        if prompt:
            params["prompt"] = prompt
        params.update(self.config.extra_params)
        params.update(extra_params or {})
        url = f"{self._keys.endpoint('authorization_endpoint')}?{urlencode(params)}"
        return LoginRequest(url=url, state=state, nonce=nonce, code_verifier=verifier)

    def handle_callback(self, params: Mapping[str, str], login: LoginRequest | Mapping[str, Any]) -> TokenSet:
        """Process the redirect back from Keycloak and return validated tokens.

        ``params`` are the query parameters of the redirect URI, ``login`` the object (or session dict) saved by
        :meth:`login_request`. Order of checks: error parameter -> state -> issuer -> code -> token exchange ->
        ID token validation (signature, iss, aud, exp, nonce, at_hash).
        """
        if not isinstance(login, LoginRequest):
            login = LoginRequest.from_session(login)
        if params.get("error"):
            raise AuthorizationError(params["error"], params.get("error_description"))
        received_state = params.get("state") or ""
        if not received_state or not hmac.compare_digest(received_state, login.state):
            raise StateMismatchError("state of the callback does not match the login request")
        # RFC 9207: Keycloak adds ``iss`` to the callback; a different issuer means a mix-up attack.
        if params.get("iss") and params["iss"] != self.config.issuer:
            raise StateMismatchError("issuer of the callback does not match the configured realm")
        code = params.get("code")
        if not code:
            raise AuthorizationError("invalid_response", "callback carries neither code nor error")
        return self.exchange_code(code, login)

    def exchange_code(self, code: str, login: LoginRequest | Mapping[str, Any]) -> TokenSet:
        """Swap an authorization code for tokens and validate the ID token against the login request's nonce."""
        if not isinstance(login, LoginRequest):
            login = LoginRequest.from_session(login)
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.config.redirect_uri}
        if login.code_verifier:
            form["code_verifier"] = login.code_verifier
        data = self._token_request(form)
        if not data.get("id_token"):
            raise TokenValidationError("token response has no id_token (is the 'openid' scope granted?)")
        claims = self.validate_id_token(data["id_token"], nonce=login.nonce, access_token=data["access_token"])
        return TokenSet.from_response(data, self._clock(), claims)

    # ================================================================== 3. token validation
    def validate_id_token(self, id_token: str, nonce: str | None = None,
                          access_token: str | None = None) -> dict[str, Any]:
        """Verify an ID token and return its claims. ``aud`` must contain this client's id."""
        claims = self._decode(id_token, audience=self.config.client_id)
        if nonce is not None and not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise TokenValidationError("nonce of the ID token does not match the login request")
        at_hash = claims.get("at_hash")
        if access_token and at_hash:
            alg = jwt.get_unverified_header(id_token).get("alg", "RS256")
            if not hmac.compare_digest(at_hash, half_hash(access_token, alg)):
                raise TokenValidationError("at_hash of the ID token does not match the access token")
        return claims

    def validate_access_token(self, token: str, audience: str | None = None) -> dict[str, Any]:
        """Verify a bearer token offline (signature, issuer, expiry) and return its claims.

        The ``aud`` claim is checked against ``audience`` or ``config.audience``; with neither set it is not
        checked (Keycloak's default audience is often just ``account``, so configure a mapper and set ``audience``
        for resource servers).
        """
        return self._decode(token, audience=audience or self.config.audience)

    def _decode(self, token: str, audience: str | None) -> dict[str, Any]:
        key = self._keys.signing_key(token)
        try:
            return jwt.decode(
                token, key.key, algorithms=list(self.config.allowed_algs), audience=audience,
                issuer=self.config.issuer, leeway=self.config.leeway,
                options={"require": ["exp", "iss"], "verify_aud": audience is not None})
        except jwt.ExpiredSignatureError as exc:
            raise TokenValidationError("token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise TokenValidationError("token audience does not match") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenValidationError("token issuer does not match the configured realm") from exc
        except jwt.PyJWTError as exc:
            raise TokenValidationError(f"token is invalid: {type(exc).__name__}") from exc

    # ================================================================== 4. refresh
    def refresh(self, tokens: TokenSet | str) -> TokenSet:
        """Use the refresh token to obtain new tokens (Keycloak rotates refresh tokens when configured to).

        Raises :class:`RefreshError`; ``err.reauth_required`` is True when the SSO session has ended or the refresh
        token expired (``invalid_grant``), meaning the user has to log in again.
        """
        previous = tokens if isinstance(tokens, TokenSet) else None
        refresh_token = tokens.refresh_token if isinstance(tokens, TokenSet) else tokens
        if not refresh_token:
            raise RefreshError("no_refresh_token", "the token set has no refresh token", reauth_required=True)
        try:
            data = self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        except TokenError as exc:
            # invalid_grant = session ended / token expired / reused; anything else may be transient.
            raise RefreshError(exc.error, exc.description, exc.status,
                               reauth_required=exc.error == "invalid_grant") from exc
        claims = None
        if data.get("id_token"):   # a refresh response carries a new ID token when 'openid' is granted
            claims = self.validate_id_token(data["id_token"], access_token=data["access_token"])
        return TokenSet.from_response(data, self._clock(), claims, previous)

    def ensure_fresh(self, tokens: TokenSet) -> TokenSet:
        """Return ``tokens`` unchanged while the access token is valid, otherwise refresh it.

        Call before every downstream API request; the returned set must replace the one in your session.
        """
        if not tokens.is_access_expired(self._clock(), self.config.refresh_margin):
            return tokens
        if not tokens.can_refresh(self._clock()):
            raise RefreshError("session_expired", "access and refresh token have expired", reauth_required=True)
        return self.refresh(tokens)

    # ================================================================== 5. logout
    def logout_url(self, tokens: TokenSet | str | None = None, post_logout_redirect_uri: str | None = None,
                   state: str | None = None) -> str:
        """URL for RP-initiated logout (OIDC): redirect the browser there to end the Keycloak SSO session.

        ``tokens`` may be the :class:`TokenSet` or the raw ID token (``id_token_hint``). Without a hint Keycloak
        asks the user to confirm. ``post_logout_redirect_uri`` must be registered on the client.
        """
        id_token = tokens.id_token if isinstance(tokens, TokenSet) else tokens
        target = post_logout_redirect_uri or self.config.post_logout_redirect_uri
        params: dict[str, str] = {"client_id": self.config.client_id}
        if id_token:
            params["id_token_hint"] = id_token
        if target:
            params["post_logout_redirect_uri"] = target
            if state:
                params["state"] = state
        return f"{self._keys.endpoint('end_session_endpoint')}?{urlencode(params)}"

    def logout_backchannel(self, tokens: TokenSet | str) -> bool:
        """End the session server-to-server by presenting the refresh token (no browser redirect needed).

        Returns True when Keycloak accepted it. Useful for API-only clients and for revoking on application logout.
        """
        refresh_token = tokens.refresh_token if isinstance(tokens, TokenSet) else tokens
        if not refresh_token:
            return False
        data, auth = self._client_auth({"refresh_token": refresh_token})
        try:
            response = self._http.request("POST", self._keys.endpoint("end_session_endpoint"), data=data, auth=auth)
        except requests.RequestException as exc:
            raise TokenError("connection_error", type(exc).__name__) from exc
        return response.status_code in (200, 204)

    # ================================================================== 6. other grants and userinfo
    def client_credentials(self, scopes: tuple[str, ...] | None = None) -> TokenSet:
        """Service-to-service token (client-credentials grant). Requires a confidential client with a service account."""
        if not self.config.is_confidential:
            raise TokenError("unauthorized_client", "client_credentials needs a client secret")
        form = {"grant_type": "client_credentials"}
        if scopes:
            form["scope"] = " ".join(scopes)
        return TokenSet.from_response(self._token_request(form), self._clock())

    def userinfo(self, access_token: str | TokenSet) -> dict[str, Any]:
        """Call the userinfo endpoint; also confirms Keycloak still considers the session active."""
        token = access_token.access_token if isinstance(access_token, TokenSet) else access_token
        try:
            response = self._http.request("GET", self._keys.endpoint("userinfo_endpoint"),
                                          headers={"Authorization": f"Bearer {token}"})
        except requests.RequestException as exc:
            raise TokenError("connection_error", type(exc).__name__) from exc
        if response.status_code != 200:
            raise TokenError("userinfo_failed", "access token rejected" if response.status_code == 401 else None,
                             response.status_code)
        return response.json()

    # ================================================================== internals
    def _client_auth(self, form: dict[str, str]) -> tuple[dict[str, str], tuple[str, str] | None]:
        """Confidential clients authenticate with HTTP Basic (client_secret_basic); public ones send client_id."""
        if self.config.client_secret:
            return form, (self.config.client_id, self.config.client_secret)
        return {**form, "client_id": self.config.client_id}, None

    def _token_request(self, form: dict[str, str]) -> dict[str, Any]:
        """POST to the token endpoint and translate failures into :class:`TokenError` (no secrets in messages)."""
        data, auth = self._client_auth(form)
        try:
            response = self._http.request("POST", self._keys.endpoint("token_endpoint"), data=data, auth=auth)
        except requests.RequestException as exc:
            raise TokenError("connection_error", f"cannot reach Keycloak ({type(exc).__name__})") from exc
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code != 200:
            raise TokenError(str(body.get("error", "server_error")), body.get("error_description"),
                             response.status_code)
        if "access_token" not in body:
            raise TokenError("invalid_response", "token response has no access_token", response.status_code)
        return body
