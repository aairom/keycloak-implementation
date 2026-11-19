"""Minimal Flask application protected by the Keycloak connector (about 80 lines of integration code).

Run it against any Keycloak client that allows the redirect URI http://localhost:9000/callback (see "Register a
client" in connector/README.md)::

    cd connector && uv venv && uv pip install -r requirements.txt flask
    export KEYCLOAK_SERVER_URL=http://localhost:8080 KEYCLOAK_REALM=demo KEYCLOAK_CLIENT_ID=<client>
    export KEYCLOAK_CLIENT_SECRET=<secret> KEYCLOAK_REDIRECT_URI=http://localhost:9000/callback
    export FLASK_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
    python examples/flask_app.py

WARNING: Flask's default session is a signed (not encrypted) cookie, so the browser can read the tokens stored in it.
That is acceptable for a demo only; in production keep tokens in a server-side session store (Flask-Session, Redis ...).
"""
from __future__ import annotations

import os
import sys
import time
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, request, session, url_for

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from keycloak_connector import (AuthorizationError, KeycloakConfig, KeycloakConnector,  # noqa: E402
                                KeycloakConnectorError, LoginRequest, RefreshError, TokenSet)


def create_app(connector: KeycloakConnector | None = None) -> Flask:
    """Application factory; tests pass a connector wired to a fake Keycloak."""
    app = Flask(__name__)
    app.secret_key = os.environ["FLASK_SECRET_KEY"] if connector is None else "test-only"
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
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
        return "<a href='/login'>Sign in</a> | <a href='/profile'>Profile</a>"

    @app.get("/login")
    def login():
        request_ = kc.login_request()
        session["login"] = request_.to_session()      # state, nonce, PKCE verifier: needed in /callback
        return redirect(request_.url)

    @app.get("/callback")
    def callback():
        pending = session.pop("login", None)
        if pending is None:
            return "No login in progress; start at /login", 400
        try:
            tokens = kc.handle_callback(request.args, LoginRequest.from_session(pending))
        except AuthorizationError as exc:             # user denied or Keycloak reported an error
            return f"Sign-in failed: {exc.error}", 401
        except KeycloakConnectorError:                # state mismatch, invalid token, Keycloak unreachable ...
            return "Sign-in failed", 400
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


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "9000")))
