"""Pure helpers for the log dashboard (no Flask / network, easy to unit test)."""
from __future__ import annotations

import base64
import json
import re
import time
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlencode

DAY_MS = 86_400_000
STATUS_RE = re.compile(r"^(\d{3}|\dxx)$", re.I)


def decode_jwt_payload(token: str | None) -> dict:
    """Decode a JWT payload **without verifying it** (display / expiry bookkeeping only).

    The token arrived over the back channel directly from Keycloak. Returns ``{}`` for anything malformed.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        return data if isinstance(data, dict) else {}
    except (IndexError, ValueError, AttributeError):
        return {}


def realm_roles(claims: dict) -> list[str]:
    hidden = {"offline_access", "uma_authorization"}
    roles = claims.get("realm_access", {}).get("roles", [])
    return sorted(r for r in roles if r not in hidden and not r.startswith("default-roles-"))


def seconds_left(exp: float | int | None, now: float | None = None) -> int:
    """Seconds until ``exp`` (never negative; 0 when unknown)."""
    if not isinstance(exp, (int, float)):
        return 0
    return max(0, int(exp - (time.time() if now is None else now)))


def build_logout_url(end_session_endpoint: str, id_token: str | None, post_logout_redirect_uri: str,
                     client_id: str) -> str:
    """RP-initiated logout URL (OpenID Connect RP-Initiated Logout 1.0)."""
    params = {"post_logout_redirect_uri": post_logout_redirect_uri, "client_id": client_id}
    if id_token:
        params["id_token_hint"] = id_token
    return f"{end_session_endpoint}?{urlencode(params)}"


def parse_day(value: str | None) -> date | None:
    """``YYYY-MM-DD`` -> date; ``None`` for empty or invalid input (a bad filter is ignored, not an error)."""
    try:
        return date.fromisoformat(value.strip()) if value and value.strip() else None
    except ValueError:
        return None


def day_start_ms(day: date) -> int:
    return int(datetime(day.year, day.month, day.day, tzinfo=timezone.utc).timestamp() * 1000)


def parse_filters(args, force_username: str | None = None) -> dict:
    """Turn query-string arguments into a validated filter dict for ``Store.query_events``.

    ``force_username`` pins the user filter (non-admins may only see their own events). The end date is
    inclusive in the UI, therefore ``date_to`` is the start of the following day.
    """
    f: dict = {}
    f["username_exact"] = force_username or ""
    f["username"] = "" if force_username else (args.get("username") or "").strip()[:100]
    f["event_type"] = (args.get("event_type") or "").strip()[:60]
    f["kind"] = (args.get("kind") or "").strip()[:30]
    source = (args.get("source") or "").strip()
    f["source"] = source if source in ("app", "keycloak") else ""
    status = (args.get("status") or "").strip()
    f["status"] = status.lower() if STATUS_RE.match(status) else ""
    f["q"] = (args.get("q") or "").strip()[:100]
    start, end = parse_day(args.get("date_from")), parse_day(args.get("date_to"))
    f["date_from"] = day_start_ms(start) if start else None
    f["date_to"] = day_start_ms(end + timedelta(days=1)) if end else None
    return f


def page_number(args) -> int:
    try:
        return max(1, int(args.get("page", 1)))
    except (TypeError, ValueError):
        return 1


def page_count(total: int, page_size: int) -> int:
    return max(1, -(-total // page_size))


def fmt_ts(ms: int | None) -> str:
    """Epoch milliseconds -> ``YYYY-MM-DD HH:MM:SS`` (UTC)."""
    if ms is None:
        return ""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def fmt_day(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%a %d %b")


def severity(event_type: str, status: int | None) -> str:
    """CSS class for a log row: ``bad``, ``warn`` or ``ok``."""
    if event_type in ("LOGIN_ERROR", "CLIENT_LOGIN_ERROR", "TOKEN_EXPIRED", "TOKEN_REFRESH_FAILED",
                      "S2S_ERROR", "ACCESS_DENIED") or (status is not None and status >= 500):
        return "bad"
    if event_type == "TOKEN_EXPIRY_WARNING" or (status is not None and status >= 400):
        return "warn"
    return "ok"
