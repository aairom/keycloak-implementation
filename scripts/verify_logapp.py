#!/usr/bin/env python3
"""Scripted browser session against the log dashboard (used by scripts/verify.sh).

Logs in through the real Keycloak login form, exercises the dashboard and prints ``PASS``/``FAIL`` lines.
Environment: LOGAPP_PUBLIC_URL, KC_HOSTNAME, DEMO_REALM, DEMO_USER_PASSWORD, DEMO_ADMIN_PASSWORD, VERIFY_INSECURE.
Variables that are not set are read from ``.env`` in the project root, so the script also works when started directly.
Exit code 0 = every check passed. Needs only the standard library plus ``requests``.
"""
from __future__ import annotations

import os
import re
import sys
import time
from html import unescape
from pathlib import Path

import requests

FAILED = 0
REQUIRED_ENV = ("DEMO_USER_PASSWORD", "DEMO_ADMIN_PASSWORD")


def load_dotenv(path: Path) -> None:
    """Fill variables that are not set yet from a ``KEY=value`` file; the real environment always wins."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key, value.strip().strip('"').strip("'"))


def keycloak_message(html: str) -> str | None:
    """The error Keycloak prints on its login form (e.g. "Invalid username or password.")."""
    m = re.search(r'kc-feedback-text[^>]*>\s*([^<]+?)\s*<', html)
    return unescape(m.group(1)) if m else None


def check(ok: bool, text: str) -> None:
    global FAILED
    print(("PASS  " if ok else "FAIL  ") + text)
    FAILED += 0 if ok else 1


def _treat_localhost_as_secure(session: requests.Session, base: str) -> None:
    """Browsers send ``Secure`` cookies to http://localhost; ``requests`` does not, so mimic the browser."""
    if base.startswith("http://"):
        for cookie in session.cookies:
            cookie.secure = False


def sign_in(base: str, username: str, password: str, verify: bool) -> requests.Session:
    """Follow /login -> Keycloak form -> /callback and return the authenticated session."""
    s = requests.Session()
    s.verify = verify
    page = s.get(f"{base}/login", timeout=20)
    _treat_localhost_as_secure(s, base)
    m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', page.text) or \
        re.search(r'<form[^>]*action="([^"]+)"[^>]*id="kc-form-login"', page.text)
    if not m:
        raise RuntimeError(f"no Keycloak login form found (landed on {page.url})")
    resp = s.post(unescape(m.group(1)), data={"username": username, "password": password}, timeout=20)
    if not resp.url.startswith(base):
        reason = keycloak_message(resp.text) or f"HTTP {resp.status_code}"
        raise RuntimeError(f"login of {username} failed: Keycloak says \"{reason}\" "
                           f"(landed on {resp.url.split('?')[0]})")
    return s


def csrf_of(session: requests.Session, base: str) -> str:
    html = session.get(f"{base}/dashboard", timeout=20).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def events(session: requests.Session, base: str, **params) -> list[dict]:
    return session.get(f"{base}/events.json", params=params, timeout=20).json()["events"]


def main() -> int:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    base = os.environ.get("LOGAPP_PUBLIC_URL", "http://localhost:8083").rstrip("/")
    verify = not os.environ.get("VERIFY_INSECURE")
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        check(False, f"{', '.join(missing)} not set: export them or create .env (scripts/init-env.sh)")
        return 1
    alice_pw, bob_pw = os.environ.get("DEMO_USER_PASSWORD", ""), os.environ.get("DEMO_ADMIN_PASSWORD", "")
    print(f"== Log dashboard ({base})")

    check(requests.get(f"{base}/healthz", timeout=15, verify=verify).json().get("database") is True,
          "health endpoint reports the database")
    anon = requests.get(f"{base}/dashboard", allow_redirects=False, timeout=15, verify=verify)
    check(anon.status_code == 302 and anon.headers["Location"].endswith("/login"), "anonymous users are sent to login")

    try:
        alice = sign_in(base, "alice", alice_pw, verify)
        bob = sign_in(base, "bob", bob_pw, verify)
    except Exception as exc:  # wrong passwords, Keycloak down ...
        check(False, f"login through Keycloak ({exc})")
        return 1
    check("Signed in as <b>alice</b>" in alice.get(f"{base}/dashboard", timeout=20).text, "alice signs in with Authorization Code + PKCE")

    # Drive some traffic: allowed and denied API calls plus a service-to-service call.
    token = csrf_of(bob, base)
    for key in ("me", "reports", "admin"):
        bob.post(f"{base}/api-call/{key}", data={"csrf": token}, timeout=30)
    bob.post(f"{base}/s2s", data={"csrf": token}, timeout=30)
    atoken = csrf_of(alice, base)
    alice.post(f"{base}/api-call/admin", data={"csrf": atoken}, timeout=30)   # alice may not -> 403

    api = {(e["username"], e["path"]): e["status"] for e in events(bob, base, kind="api")}
    check(api.get(("bob", "/api/admin")) == 200 and api.get(("alice", "/api/admin")) == 403,
          "API calls are logged with method, path and status (bob 200, alice 403)")
    check(all(e["duration_ms"] is not None for e in events(bob, base, kind="api")), "API calls record their duration")
    s2s = events(bob, base, kind="s2s")
    check(bool(s2s) and s2s[0]["username"] == "service-account-demo-service" and s2s[0]["status"] == 200,
          "service-to-service request is logged as the demo-service identity")
    check("LOGIN" in {e["event_type"] for e in events(bob, base, source="app")}, "application login events are logged")
    check(any(e["method"] == "GET" and e["path"] == "/dashboard" for e in events(bob, base, kind="access")),
          "HTTP access log has method, path and status")

    # Keycloak's own events arrive through the background sync (interval 10 s by default).
    deadline = time.time() + 45
    kc = []
    while time.time() < deadline:
        kc = events(bob, base, source="keycloak", event_type="LOGIN")
        if {"alice", "bob"} <= {e["username"] for e in kc}:
            break
        time.sleep(3)
    check({"alice", "bob"} <= {e["username"] for e in kc}, "Keycloak LOGIN events are synchronised (admin REST, view-events)")

    # Filters.
    check({e["username"] for e in events(bob, base, username="ali")} == {"alice"}, "admin filter by username")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    check(len(events(bob, base, date_from=today, date_to=today)) > 0, "filter by date range")
    check(len(events(bob, base, date_from="2000-01-01", date_to="2000-01-02")) == 0, "date range without events is empty")
    check(all(e["status"] == 403 for e in events(bob, base, status="403")) and events(bob, base, status="403"),
          "filter by status code")
    check(all(400 <= e["status"] < 500 for e in events(bob, base, status="4xx")), "filter by status class (4xx)")
    check(len(events(bob, base, event_type="API_CALL")) > 0, "filter by event type")

    # Authorization inside the dashboard.
    check({e["username"] for e in events(alice, base, username="bob")} <= {"alice"},
          "non-admin cannot read other users' events (username filter is pinned)")
    check(alice.get(f"{base}/admin", timeout=20).status_code == 403, "admin panel is forbidden for alice")
    panel = bob.get(f"{base}/admin", timeout=20)
    check(panel.status_code == 200 and "Most active users" in panel.text and "Failed attempts" in panel.text,
          "admin panel shows aggregate statistics for bob")
    check("ACCESS_DENIED" in {e["event_type"] for e in events(bob, base, event_type="ACCESS_DENIED")}, "denied admin access is logged")

    # Logout is logged and ends the session.
    alice.get(f"{base}/logout", timeout=20)
    check(alice.get(f"{base}/dashboard", allow_redirects=False, timeout=20).status_code == 302, "logout ends the session")
    check("LOGOUT" in {e["event_type"] for e in events(bob, base, event_type="LOGOUT")}, "logout event is logged")

    print()
    print("LOGAPP VERIFY OK" if FAILED == 0 else "LOGAPP VERIFY FAILED")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
