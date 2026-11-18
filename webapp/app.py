"""Demo web application: an OpenID Connect confidential client for Keycloak.

* Authorization Code flow with PKCE (S256) via Authlib
* Server-side session holds the tokens (the browser only gets a signed session cookie)
* Calls the protected demo API with the user's access token
* RP-initiated logout (ends the Keycloak SSO session too)

Configuration comes exclusively from environment variables (see ``.env.example``).
"""
from __future__ import annotations

import logging
import os
import secrets

import requests
from authlib.integrations.flask_client import OAuth
from flask import (Flask, abort, flash, redirect, render_template, request, session,
                   url_for)

from helpers import build_logout_url, decode_jwt_payload, realm_roles, seconds_left

log = logging.getLogger("demo-webapp")

REQUIRED = ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "WEBAPP_SESSION_SECRET",
            "WEBAPP_PUBLIC_URL", "API_BASE_URL")

API_CALLS = {  # key -> (method, path, label)
    "me": ("GET", "/api/me", "Who am I?"),
    "reports_read": ("GET", "/api/reports", "Read reports (role app-user)"),
    "reports_write": ("POST", "/api/reports", "Write report (role app-admin)"),
    "admin": ("GET", "/api/admin", "Admin panel (role app-admin)"),
}


def create_app(env=None, oauth: OAuth | None = None, http=requests) -> Flask:
    """Application factory. ``oauth`` and ``http`` can be injected in tests."""
    env = os.environ if env is None else env
    missing = [k for k in REQUIRED if not env.get(k)]
    if missing:
        raise RuntimeError(f"missing environment variables: {', '.join(missing)}")

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=env["WEBAPP_SESSION_SECRET"],
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=env["WEBAPP_PUBLIC_URL"].startswith("https://"),
    )
    public_url = env["WEBAPP_PUBLIC_URL"].rstrip("/")
    client_id = env["OIDC_CLIENT_ID"]
    api_base = env["API_BASE_URL"].rstrip("/")

    if oauth is None:
        oauth = OAuth(app)
        oauth.register(
            name="keycloak",
            client_id=client_id,
            client_secret=env["OIDC_CLIENT_SECRET"],
            server_metadata_url=env["OIDC_DISCOVERY_URL"],
            client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
        )
    kc = oauth.keycloak

    def current_user():
        return session.get("user")

    @app.context_processor
    def inject():
        return {"user": current_user(), "client_id": client_id}

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/login")
    def login():
        return kc.authorize_redirect(f"{public_url}/callback")

    @app.get("/callback")
    def callback():
        try:
            token = kc.authorize_access_token()
        except Exception as exc:  # state mismatch, denied consent, bad code ...
            log.warning("login failed: %s", exc)
            flash("Login failed. Please try again.", "error")
            return redirect(url_for("index"))
        claims = token.get("userinfo") or {}
        access_claims = decode_jwt_payload(token["access_token"])
        session.clear()
        session["user"] = {
            "name": claims.get("name") or claims.get("preferred_username"),
            "username": claims.get("preferred_username"),
            "email": claims.get("email"),
        }
        session["tokens"] = {"access_token": token["access_token"], "id_token": token.get("id_token"),
                             "refresh_token": token.get("refresh_token")}
        session["id_claims"] = claims
        session["csrf"] = secrets.token_urlsafe(16)
        log.info("user %s logged in (roles=%s)", claims.get("preferred_username"),
                 realm_roles(access_claims))
        return redirect(url_for("profile"))

    @app.get("/profile")
    def profile():
        if not current_user():
            return redirect(url_for("login"))
        access_claims = decode_jwt_payload(session["tokens"]["access_token"])
        return render_template("profile.html", id_claims=session["id_claims"],
                               access_claims=access_claims, roles=realm_roles(access_claims),
                               groups=access_claims.get("groups", []),
                               expires_in=seconds_left(access_claims), api_calls=API_CALLS,
                               csrf=session["csrf"], api_result=session.pop("api_result", None))

    @app.post("/api-call/<key>")
    def api_call(key):
        if not current_user():
            return redirect(url_for("login"))
        if request.form.get("csrf") != session.get("csrf"):
            abort(400, "invalid CSRF token")
        if key not in API_CALLS:
            abort(404)
        method, path, label = API_CALLS[key]
        try:
            resp = http.request(method, api_base + path, timeout=5,
                                headers={"Authorization": f"Bearer {session['tokens']['access_token']}"})
            try:
                body = resp.json()
            except ValueError:
                body = {"raw": resp.text}
            session["api_result"] = {"label": label, "request": f"{method} {path}",
                                     "status": resp.status_code, "body": body}
        except requests.RequestException as exc:
            session["api_result"] = {"label": label, "request": f"{method} {path}",
                                     "status": 0, "body": {"error": f"API unreachable: {exc}"}}
        return redirect(url_for("profile"))

    @app.get("/logout")
    def logout():
        id_token = (session.get("tokens") or {}).get("id_token")
        session.clear()
        try:
            end_session = kc.load_server_metadata()["end_session_endpoint"]
        except Exception:  # identity provider unreachable: still log out locally
            return redirect(url_for("index"))
        return redirect(build_logout_url(end_session, id_token, f"{public_url}/", client_id))

    @app.get("/healthz")
    def healthz():
        return {"status": "UP"}

    return app


def get_wsgi_app() -> Flask:  # gunicorn entry point: ``app:get_wsgi_app()``
    logging.basicConfig(level=logging.INFO)
    return create_app()


if __name__ == "__main__":  # local development server only
    logging.basicConfig(level=logging.INFO)
    create_app().run(host=os.environ.get("WEBAPP_HOST", "127.0.0.1"),
                     port=int(os.environ.get("WEBAPP_PORT", "8081")))
