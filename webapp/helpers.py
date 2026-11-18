"""Pure helper functions for the demo web app (no Flask / network access, easy to unit test)."""
from __future__ import annotations

import base64
import json
import time


def decode_jwt_payload(token: str) -> dict:
    """Decode a JWT payload **without verifying it** (display only).

    The web app received the token directly from Keycloak over the back channel, so it is
    trusted for display purposes. Resource servers (see ``api/``) always verify signatures.
    Returns an empty dict for anything that is not a well-formed JWT.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        return data if isinstance(data, dict) else {}
    except (IndexError, ValueError, AttributeError):
        return {}


def realm_roles(access_token_claims: dict) -> list[str]:
    """Realm roles from an access token, without Keycloak's built-in default roles."""
    roles = access_token_claims.get("realm_access", {}).get("roles", [])
    hidden = {"offline_access", "uma_authorization"}
    return sorted(r for r in roles if r not in hidden and not r.startswith("default-roles-"))


def seconds_left(claims: dict, now: float | None = None) -> int:
    """Seconds until ``exp`` (never negative; 0 when ``exp`` is missing)."""
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        return 0
    return max(0, int(exp - (time.time() if now is None else now)))


def build_logout_url(end_session_endpoint: str, id_token: str | None, post_logout_redirect_uri: str,
                     client_id: str) -> str:
    """RP-initiated logout URL (OpenID Connect RP-Initiated Logout 1.0)."""
    from urllib.parse import urlencode

    params = {"post_logout_redirect_uri": post_logout_redirect_uri, "client_id": client_id}
    if id_token:
        params["id_token_hint"] = id_token
    return f"{end_session_endpoint}?{urlencode(params)}"
