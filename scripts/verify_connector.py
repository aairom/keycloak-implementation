#!/usr/bin/env python3
"""Integration test of the Keycloak connector against the running demo Keycloak (used by scripts/verify.sh).

Drives the real flows through ``connector/keycloak_connector``: discovery, Authorization Code + PKCE with a
scripted browser (the Keycloak login form), token validation, userinfo, refresh, client credentials and both
logout styles, plus negative cases (wrong state, tampered token, ended session).

It reuses the registered ``demo-logapp`` client (redirect URI ``<LOGAPP_PUBLIC_URL>/callback``). The callback is read
from the redirect *Location* header and never requested, so the dashboard does not consume the code.

Environment (read from ``.env`` when not set): KC_HOSTNAME, DEMO_REALM, LOGAPP_PUBLIC_URL, LOGAPP_CLIENT_SECRET,
SERVICE_CLIENT_SECRET, DEMO_USER_PASSWORD, DEMO_ADMIN_PASSWORD, VERIFY_INSECURE.
Exit code 0 = every check passed. Passwords and tokens are never printed.
"""
from __future__ import annotations

import os
import re
import sys
from html import unescape
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "connector"))

from keycloak_connector import (KeycloakConfig, KeycloakConnector, KeycloakConnectorError,  # noqa: E402
                                RefreshError, StateMismatchError, TokenValidationError)
from verify_logapp import _treat_localhost_as_secure, keycloak_message, load_dotenv  # noqa: E402

FAILED = 0
REQUIRED_ENV = ("KC_HOSTNAME", "LOGAPP_CLIENT_SECRET", "SERVICE_CLIENT_SECRET", "DEMO_USER_PASSWORD",
                "DEMO_ADMIN_PASSWORD")
FORM_PATTERNS = (r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', r'<form[^>]*action="([^"]+)"[^>]*id="kc-form-login"')


def check(ok: bool, text: str) -> None:
    global FAILED
    print(("PASS  " if ok else "FAIL  ") + text)
    FAILED += 0 if ok else 1


def raises(exc_type: type[BaseException], func, *args, **kwargs) -> bool:
    """True when ``func`` raises ``exc_type`` (used for the negative checks)."""
    try:
        func(*args, **kwargs)
    except exc_type:
        return True
    return False


def make_connector(env: dict[str, str], client_id: str, secret_var: str, verify: bool) -> KeycloakConnector:
    """Connector for one of the demo clients; the redirect URI is the dashboard's registered callback."""
    public = env.get("LOGAPP_PUBLIC_URL", "http://localhost:8083").rstrip("/")
    config = KeycloakConfig(server_url=env["KC_HOSTNAME"], realm=env.get("DEMO_REALM", "demo"), client_id=client_id,
                            client_secret=env[secret_var], redirect_uri=f"{public}/callback",
                            post_logout_redirect_uri=f"{public}/", verify=verify)
    return KeycloakConnector(config)


def browser_login(url: str, username: str, password: str, redirect_uri: str, verify: bool) -> dict[str, str]:
    """Play the browser: open the authorization URL, submit the login form, return the callback parameters.

    The final redirect to ``redirect_uri`` is *not* followed; its query string is what the application would receive.
    """
    s = requests.Session()
    s.verify = verify
    page = s.get(url, timeout=20)
    _treat_localhost_as_secure(s, redirect_uri)
    m = next((m for m in (re.search(p, page.text) for p in FORM_PATTERNS) if m), None)
    if not m:
        raise RuntimeError(f"no Keycloak login form found (landed on {page.url.split('?')[0]})")
    resp = s.post(unescape(m.group(1)), data={"username": username, "password": password},
                  allow_redirects=False, timeout=20)
    location = resp.headers.get("Location", "")
    if not location.startswith(redirect_uri):
        reason = keycloak_message(resp.text) or f"HTTP {resp.status_code}"
        raise RuntimeError(f"login of {username} failed: Keycloak says \"{reason}\"")
    return dict(parse_qsl(urlparse(location).query))


def sign_in(kc: KeycloakConnector, username: str, password: str, verify: bool):
    """Connector login end to end; returns ``(login_request, params, tokens)``."""
    login = kc.login_request()
    params = browser_login(login.url, username, password, kc.config.redirect_uri, verify)
    return login, params, kc.handle_callback(params, login)


def run(env: dict[str, str], verify: bool) -> int:
    """All checks; returns the process exit code."""
    base = env["KC_HOSTNAME"].rstrip("/")
    print(f"== Keycloak connector ({base}, realm {env.get('DEMO_REALM', 'demo')})")
    kc = make_connector(env, "demo-logapp", "LOGAPP_CLIENT_SECRET", verify)

    # 1. initialisation
    try:
        kc.initialize()
        check(True, "initialize(): discovery document and signing keys loaded, issuer matches the realm")
    except KeycloakConnectorError as exc:
        check(False, f"initialize() ({exc})")
        return 1
    check(kc.health(), "health(): readiness probe succeeds")
    wrong = KeycloakConnector(KeycloakConfig(**{**kc.config.__dict__, "realm": "no-such-realm"}))
    check(raises(KeycloakConnectorError, wrong.initialize), "initialize() fails fast for an unknown realm")

    # 2. login with Authorization Code + PKCE
    try:
        login, params, tokens = sign_in(kc, "alice", env["DEMO_USER_PASSWORD"], verify)
    except Exception as exc:  # noqa: BLE001 - wrong password, Keycloak down ...
        check(False, f"login through Keycloak ({exc})")
        return 1
    check(params.get("state") == login.state and params.get("iss") == kc.config.issuer,
          "callback carries the state and the RFC 9207 issuer")
    check(tokens.claims.get("preferred_username") == "alice" and tokens.claims.get("nonce") == login.nonce,
          "handle_callback(): code exchanged, ID token validated (signature, iss, aud, nonce, at_hash)")
    access = kc.validate_access_token(tokens.access_token)
    check("app-user" in access.get("realm_access", {}).get("roles", []), "validate_access_token(): alice has the app-user role")
    check(kc.userinfo(tokens).get("preferred_username") == "alice", "userinfo(): Keycloak accepts the access token")

    # 3. negative cases
    check(raises(StateMismatchError, kc.handle_callback, {**params, "state": "forged"}, login),
          "a callback with a forged state is rejected")
    check(raises(TokenValidationError, kc.validate_access_token, tokens.access_token[:-4] + "AAAA"),
          "an access token with a damaged signature is rejected")
    check(raises(TokenValidationError, kc.validate_access_token, tokens.access_token, "not-the-audience"),
          "an access token for another audience is rejected")

    # 4. refresh
    renewed = kc.refresh(tokens)
    check(renewed.access_token != tokens.access_token and renewed.claims.get("preferred_username") == "alice",
          "refresh(): new access token issued, identity kept")
    check(kc.ensure_fresh(renewed) is renewed, "ensure_fresh(): a valid token is returned unchanged")
    check(kc.validate_access_token(renewed.access_token)["preferred_username"] == "alice", "refreshed token validates")

    # 5. client credentials (service account)
    service = make_connector(env, "demo-service", "SERVICE_CLIENT_SECRET", verify)
    svc = service.client_credentials()
    check(service.validate_access_token(svc.access_token).get("azp") == "demo-service" and svc.refresh_token is None,
          "client_credentials(): service-account token for demo-service")

    # 6. logout: front channel (RP-initiated) ends alice's session
    ended = requests.get(kc.logout_url(renewed), allow_redirects=False, timeout=20, verify=verify)
    check(ended.status_code == 302 and ended.headers.get("Location", "").startswith(kc.config.post_logout_redirect_uri),
          "logout_url(): RP-initiated logout redirects to the registered post-logout URI")
    try:
        kc.refresh(renewed)
        check(False, "refresh after logout must fail")
    except RefreshError as exc:
        check(exc.reauth_required, "refresh after logout asks the user to sign in again (invalid_grant)")

    # 7. logout: back channel for bob
    try:
        _, _, bob = sign_in(kc, "bob", env["DEMO_ADMIN_PASSWORD"], verify)
    except Exception as exc:  # noqa: BLE001
        check(False, f"login of bob ({exc})")
        return 1
    check("app-admin" in kc.validate_access_token(bob.access_token).get("realm_access", {}).get("roles", []),
          "second user (bob) signs in with the app-admin role")
    check(kc.logout_backchannel(bob) is True, "logout_backchannel(): session ended server to server")
    check(raises(RefreshError, kc.refresh, bob), "refresh after back-channel logout fails")

    print()
    print("CONNECTOR VERIFY OK" if FAILED == 0 else "CONNECTOR VERIFY FAILED")
    return 1 if FAILED else 0


def main() -> int:
    load_dotenv(ROOT / ".env")
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        check(False, f"{', '.join(missing)} not set: export them or create .env (scripts/init-env.sh)")
        return 1
    return run(dict(os.environ), verify=not os.environ.get("VERIFY_INSECURE"))


if __name__ == "__main__":
    sys.exit(main())
