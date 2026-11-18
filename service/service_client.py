"""Service-to-service client: OAuth 2.0 client credentials grant against Keycloak, then a call to the demo API.

Usage (with the stack running):
    set -a; . ./.env; set +a
    .venv/bin/python service/service_client.py

Environment: KC_HOSTNAME, DEMO_REALM (default "demo"), SERVICE_CLIENT_ID (default "demo-service"),
SERVICE_CLIENT_SECRET, API_PUBLIC_URL.
The access token is cached in memory until shortly before it expires.
"""
from __future__ import annotations

import json
import os
import sys
import time

import requests


class ServiceClient:
    """Authenticates as a machine identity (no user) and calls the protected API."""

    def __init__(self, token_url: str, client_id: str, client_secret: str, api_base: str,
                 http=requests, skew: int = 30, clock=time.time):
        self.token_url, self.client_id, self.client_secret = token_url, client_id, client_secret
        self.api_base = api_base.rstrip("/")
        self._http, self._skew, self._clock = http, skew, clock
        self._token: str | None = None
        self._expires_at = 0.0

    def token(self) -> str:
        """Return a valid access token, requesting a new one when missing or about to expire."""
        if self._token is None or self._clock() >= self._expires_at - self._skew:
            resp = self._http.post(
                self.token_url, timeout=10,
                data={"grant_type": "client_credentials", "client_id": self.client_id,
                      "client_secret": self.client_secret})
            resp.raise_for_status()
            body = resp.json()
            self._token = body["access_token"]
            self._expires_at = self._clock() + int(body.get("expires_in", 60))
        return self._token

    def get(self, path: str):
        """GET an API path with the service token; returns the HTTP response."""
        return self._http.get(self.api_base + path, timeout=10,
                              headers={"Authorization": f"Bearer {self.token()}"})


def from_env(env=os.environ) -> ServiceClient:
    missing = [k for k in ("KC_HOSTNAME", "SERVICE_CLIENT_SECRET", "API_PUBLIC_URL") if not env.get(k)]
    if missing:
        raise SystemExit(f"missing environment variables: {', '.join(missing)}")
    realm = env.get("DEMO_REALM", "demo")
    return ServiceClient(f"{env['KC_HOSTNAME'].rstrip('/')}/realms/{realm}/protocol/openid-connect/token",
                         env.get("SERVICE_CLIENT_ID", "demo-service"), env["SERVICE_CLIENT_SECRET"],
                         env["API_PUBLIC_URL"])


def main() -> int:
    resp = from_env().get("/api/service/data")
    print(f"HTTP {resp.status_code}")
    print(json.dumps(resp.json(), indent=2))
    return 0 if resp.ok else 1


if __name__ == "__main__":
    sys.exit(main())
