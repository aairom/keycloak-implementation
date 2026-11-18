"""OAuth 2.0 client credentials grant with an in-memory token cache (service-to-service authentication)."""
from __future__ import annotations

import threading
import time

import requests


class TokenSource:
    """Hands out a valid access token for a machine identity, re-requesting it shortly before it expires.

    Used twice by the log app: with the ``demo-logapp`` identity to read Keycloak events (this needs the
    ``kc-admin-api`` scope: Keycloak 26.8 rejects Admin REST calls whose token lacks the admin API audience),
    and with the ``demo-service`` identity for the service-to-service probe against the demo API.
    """

    def __init__(self, token_url: str, client_id: str, client_secret: str, http=requests,
                 skew: int = 30, clock=time.time, scope: str | None = None):
        self.token_url, self.client_id, self._secret, self.scope = token_url, client_id, client_secret, scope
        self._http, self._skew, self._clock = http, skew, clock
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = threading.Lock()

    def token(self) -> str:
        with self._lock:
            if self._token is None or self._clock() >= self._expires_at - self._skew:
                data = {"grant_type": "client_credentials", "client_id": self.client_id,
                        "client_secret": self._secret}
                if self.scope:
                    data["scope"] = self.scope
                resp = self._http.post(self.token_url, timeout=10, data=data)
                resp.raise_for_status()
                body = resp.json()
                self._token = body["access_token"]
                self._expires_at = self._clock() + int(body.get("expires_in", 60))
            return self._token

    def invalidate(self) -> None:
        """Forget the cached token (e.g. after the resource server answered 401)."""
        with self._lock:
            self._token = None
