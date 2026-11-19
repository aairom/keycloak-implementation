"""Minimal Flask application protected by the Keycloak connector (about 80 lines of integration code).

Run it against any Keycloak client that allows the redirect URI http://localhost:9000/callback (see "Register a
client" in connector/README.md)::

    cd connector && uv venv && uv pip install -r requirements.txt flask
    export KEYCLOAK_SERVER_URL=http://localhost:8080 KEYCLOAK_REALM=demo KEYCLOAK_CLIENT_ID=<client>
    export KEYCLOAK_CLIENT_SECRET=<secret> KEYCLOAK_REDIRECT_URI=http://localhost:9000/callback
    python examples/flask_app.py      # FLASK_SECRET_KEY is optional: a random one is generated per start

For the demo stack of this repository, `scripts/run_connector_example.sh` sets all of this from `.env`.

WARNING: Flask's default session is a signed (not encrypted) cookie, so the browser can read the tokens stored in it.
That is acceptable for a demo only; in production keep tokens in a server-side session store (Flask-Session, Redis ...).
"""
from __future__ import annotations

import logging
import os
import secrets
import sys
import time
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, request, session, url_for
from markupsafe import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keycloak_connector import (AuthorizationError, ConfigError, DiscoveryError, KeycloakConfig, KeycloakConnector,  # noqa: E402
                                KeycloakConnectorError, LoginRequest, RefreshError, TokenSet)


log = logging.getLogger("flask_app")

PAGE = ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Keycloak connector example</title>"
        "<style>body{font:18px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem}"
        "a{margin-right:1rem}code{background:#eee;padding:.1rem .3rem}.err{color:#a00}</style>{body}")


def page(body: str, status: int = 200):
    """Wrap a fragment in a small, readable HTML page."""
    return PAGE.replace("{body}", body), status


def create_app(connector: KeycloakConnector | None = None) -> Flask:
    """Application factory; tests pass a connector wired to a fake Keycloak."""
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)   # random key: sessions end on restart
    # Cookies are shared between ports on localhost, so use a name no other local app (default: "session") uses.
    app.config.update(SESSION_COOKIE_NAME="connector_example_session", SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax")
    kc = connector or KeycloakConnector(KeycloakConfig.from_env()).initialize()   # fail at start-up if misconfigured

    def login_required(view):
        """Redirect anonymous users to /login; refresh the access token when it is about to expire."""
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "tokens" not in session:
                return redirect(url_for("login"))
            try:
                tokens = kc.ensure_fresh(TokenSet.from_dict(session["tokens"]))
            except RefreshError:                      # session ended at Keycloak or refresh token expired
                session.clear()
                return redirect(url_for("login"))
            session["tokens"] = tokens.to_dict()      # keep rotated tokens
            return view(tokens, *args, **kwargs)
        return wrapper

    @app.get("/")
    def index():
        return page("<h1>Keycloak connector example</h1><p><a href='/login'>Sign in</a>"
                    "<a href='/profile'>Profile</a><a href='/logout'>Sign out</a></p>")

    @app.get("/login")
    def login():
        request_ = kc.login_request()
        session["login"] = request_.to_session()      # state, nonce, PKCE verifier: needed in /callback
        return redirect(request_.url)

    @app.get("/callback")
    def callback():
        pending = session.pop("login", None)
        if pending is None:
            log.warning("callback without a login in progress (cookie missing: host name differs or cookies blocked)")
            return page("<h1 class=err>No login in progress</h1><p>The browser did not send the session cookie. "
                        "Open this app with the <b>same host name</b> as the registered redirect URI "
                        f"(<code>{kc.config.redirect_uri}</code>), for example <code>localhost</code>, "
                        "not <code>127.0.0.1</code>.</p><p><a href='/login'>Try again</a></p>", 400)
        try:
            tokens = kc.handle_callback(request.args, LoginRequest.from_session(pending))
        except AuthorizationError as exc:             # user denied or Keycloak reported an error
            log.warning("sign-in refused by Keycloak: %s", exc.error)
            return page(f"<h1 class=err>Sign-in failed</h1><p>Keycloak answered: <code>{escape(exc.error)}</code></p>"
                        "<p><a href='/login'>Try again</a></p>", 401)
        except KeycloakConnectorError as exc:         # state mismatch, invalid token, Keycloak unreachable ...
            # Messages of the connector never contain tokens or secrets, so they are safe to log and to show.
            log.warning("sign-in failed: %s: %s", type(exc).__name__, exc)
            return page(f"<h1 class=err>Sign-in failed</h1><p><code>{type(exc).__name__}</code>: {escape(str(exc))}"
                        "</p><p><a href='/login'>Try again</a></p>", 400)
        session["tokens"] = tokens.to_dict()
        return redirect(url_for("profile"))

    @app.get("/profile")
    @login_required
    def profile(tokens: TokenSet):
        claims = kc.validate_access_token(tokens.access_token)
        return jsonify(user=tokens.claims.get("preferred_username"),
                       roles=claims.get("realm_access", {}).get("roles", []),
                       access_token_expires_in=round(tokens.expires_in(time.time())))

    @app.get("/logout")
    def logout():
        tokens = TokenSet.from_dict(session["tokens"]) if "tokens" in session else None
        session.clear()
        return redirect(kc.logout_url(tokens))        # ends the Keycloak SSO session too

    return app


def main() -> int:
    """Start the example; print what is missing instead of a traceback when the configuration is incomplete."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        app = create_app()
    except ConfigError as exc:
        print(f"{exc}\n\nSet the KEYCLOAK_* variables (see the docstring at the top of this file), or run "
              f"scripts/run_connector_example.sh to use the demo stack.", file=sys.stderr)
        return 2
    except DiscoveryError as exc:
        print(f"Keycloak is not reachable or misconfigured: {exc}", file=sys.stderr)
        return 3
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "9000")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
