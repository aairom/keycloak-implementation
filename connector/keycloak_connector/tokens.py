"""Value objects exchanged with the application: the login request to keep in the session and the token set."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class LoginRequest:
    """Result of :meth:`KeycloakConnector.login_request`.

    Redirect the browser to ``url`` and keep the rest (``to_session()``) in the *server-side* session until the
    callback arrives. ``state`` defends against CSRF, ``nonce`` binds the ID token to this request and
    ``code_verifier`` (PKCE) binds the authorization code to this client instance.
    """

    url: str
    state: str
    nonce: str
    code_verifier: str | None = None

    def to_session(self) -> dict[str, str | None]:
        """JSON-friendly form for a session store (the URL is not needed after the redirect)."""
        return {"state": self.state, "nonce": self.nonce, "code_verifier": self.code_verifier}

    @classmethod
    def from_session(cls, data: Mapping[str, Any]) -> "LoginRequest":
        return cls(url="", state=data["state"], nonce=data["nonce"], code_verifier=data.get("code_verifier"))

    def __repr__(self) -> str:  # keep verifier/nonce out of logs
        return "LoginRequest(url=<redacted>, state=<redacted>)"


@dataclass(frozen=True)
class TokenSet:
    """Tokens returned by Keycloak plus their expiry times (epoch seconds).

    ``claims`` holds the validated ID token claims (empty for client-credentials or refresh without ID token).
    The ``repr`` never shows token values.
    """

    access_token: str
    expires_at: float
    refresh_token: str | None = None
    refresh_expires_at: float | None = None   # None when the refresh token does not expire (offline) or is absent
    id_token: str | None = None
    token_type: str = "Bearer"
    scope: str = ""
    claims: Mapping[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ expiry helpers
    def expires_in(self, now: float) -> float:
        return self.expires_at - now

    def is_access_expired(self, now: float, margin: float = 0) -> bool:
        """True when the access token is expired or will be within ``margin`` seconds."""
        return now >= self.expires_at - margin

    def can_refresh(self, now: float) -> bool:
        """True when a refresh token exists and has not expired."""
        if not self.refresh_token:
            return False
        return self.refresh_expires_at is None or now < self.refresh_expires_at

    # ------------------------------------------------------------------ construction and storage
    @classmethod
    def from_response(cls, data: Mapping[str, Any], now: float, claims: Mapping[str, Any] | None = None,
                      previous: "TokenSet | None" = None) -> "TokenSet":
        """Build from a token-endpoint JSON body. ``previous`` supplies values a refresh response may omit."""
        refresh_in = data.get("refresh_expires_in")
        refresh_token = data.get("refresh_token") or (previous.refresh_token if previous else None)
        if data.get("refresh_token"):
            refresh_expires_at = now + refresh_in if refresh_in else None   # 0 = offline token, no expiry
        else:
            refresh_expires_at = previous.refresh_expires_at if previous else None
        return cls(
            access_token=data["access_token"],
            expires_at=now + float(data.get("expires_in", 0)),
            refresh_token=refresh_token,
            refresh_expires_at=refresh_expires_at,
            id_token=data.get("id_token") or (previous.id_token if previous else None),
            token_type=data.get("token_type", "Bearer"),
            scope=data.get("scope", ""),
            claims=dict(claims) if claims is not None else (dict(previous.claims) if previous else {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"access_token": self.access_token, "expires_at": self.expires_at,
                "refresh_token": self.refresh_token, "refresh_expires_at": self.refresh_expires_at,
                "id_token": self.id_token, "token_type": self.token_type, "scope": self.scope,
                "claims": dict(self.claims)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TokenSet":
        return cls(**{k: data[k] for k in ("access_token", "expires_at") }, **{
            k: data[k] for k in ("refresh_token", "refresh_expires_at", "id_token", "token_type", "scope", "claims")
            if k in data})

    def __repr__(self) -> str:
        return (f"TokenSet(expires_at={self.expires_at:.0f}, has_refresh={bool(self.refresh_token)}, "
                f"scope={self.scope!r})")
