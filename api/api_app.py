"""Demo REST API (OAuth 2.0 resource server) protected by Keycloak.

Endpoints
    GET  /api/health        public liveness probe
    GET  /api/me            any valid token: identity, realm roles, groups
    GET  /api/reports       needs permission reports#read   (role app-user  or app-admin)
    POST /api/reports       needs permission reports#write  (role app-admin)
    GET  /api/admin         needs permission admin-panel#access (role app-admin)
    GET  /api/service/data  needs permission service-data#read  (service account, role app-service)

Authentication is done locally (JWT signature check); authorization is delegated to Keycloak
Authorization Services, which evaluates the policies defined in the realm.
"""
from __future__ import annotations

import logging
import os
from functools import wraps

from flask import Flask, g, jsonify, request

from api_auth import (AuthError, PolicyDecisionClient, TokenValidator, discover,
                      extract_bearer)

log = logging.getLogger("demo-api")


def build_dependencies(env) -> tuple[TokenValidator, PolicyDecisionClient]:
    """Create the validator and PDP client from environment settings (discovery over the back channel)."""
    meta = discover(env["OIDC_DISCOVERY_URL"])
    validator = TokenValidator(issuer=env["OIDC_ISSUER"], audience=env["API_AUDIENCE"],
                               jwks_uri=meta["jwks_uri"])
    pdp = PolicyDecisionClient(meta["token_endpoint"], audience=env["API_AUDIENCE"])
    return validator, pdp


def create_app(validator: TokenValidator | None = None, pdp: PolicyDecisionClient | None = None,
               env=None) -> Flask:
    """Application factory. Dependencies are lazily built from ``env`` when not injected."""
    app = Flask(__name__)
    env = os.environ if env is None else env
    deps = {"validator": validator, "pdp": pdp}

    def get_deps():
        if deps["validator"] is None or deps["pdp"] is None:
            deps["validator"], deps["pdp"] = build_dependencies(env)
        return deps["validator"], deps["pdp"]

    def authenticate():
        """Populate ``g.claims`` / ``g.token`` or raise AuthError."""
        token = extract_bearer(request.headers.get("Authorization"))
        v, _ = get_deps()
        g.token, g.claims = token, v.validate(token)

    def require_permission(resource: str, scope: str):
        """Decorator: authenticate, then ask Keycloak for a decision on ``resource#scope``."""
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                try:
                    authenticate()
                except AuthError as exc:
                    return _unauthorized(str(exc))
                _, policy = get_deps()
                if not policy.is_permitted(g.token, resource, scope):
                    return jsonify(error="forbidden",
                                   message=f"permission {resource}#{scope} denied"), 403
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    @app.errorhandler(Exception)
    def unexpected(exc):  # identity provider unreachable, etc.
        if hasattr(exc, "code") and isinstance(exc.code, int):  # werkzeug HTTP errors
            return jsonify(error=exc.name.lower().replace(" ", "_")), exc.code
        log.exception("unhandled error")
        return jsonify(error="upstream_unavailable"), 503

    @app.get("/api/health")
    def health():
        return jsonify(status="UP")

    @app.get("/api/me")
    def me():
        try:
            authenticate()
        except AuthError as exc:
            return _unauthorized(str(exc))
        c = g.claims
        return jsonify(sub=c["sub"], username=c.get("preferred_username"),
                       email=c.get("email"),
                       roles=c.get("realm_access", {}).get("roles", []),
                       groups=c.get("groups", []))

    @app.get("/api/reports")
    @require_permission("reports", "read")
    def reports_read():
        return jsonify(reports=[{"id": 1, "title": "Q1 summary"}, {"id": 2, "title": "Q2 summary"}],
                       requested_by=g.claims.get("preferred_username"))

    @app.post("/api/reports")
    @require_permission("reports", "write")
    def reports_write():
        return jsonify(status="created", id=3, created_by=g.claims.get("preferred_username")), 201

    @app.get("/api/admin")
    @require_permission("admin-panel", "access")
    def admin():
        return jsonify(message="Welcome to the admin panel",
                       user=g.claims.get("preferred_username"))

    @app.get("/api/service/data")
    @require_permission("service-data", "read")
    def service_data():
        # Reached by machine identities (client credentials grant); no human user is involved.
        return jsonify(data=[{"metric": "queue_depth", "value": 42}],
                       caller=g.claims.get("preferred_username"), client=g.claims.get("azp"))

    return app


def _unauthorized(message: str):
    resp = jsonify(error="unauthorized", message=message)
    resp.status_code = 401
    resp.headers["WWW-Authenticate"] = 'Bearer realm="demo"'
    return resp


if __name__ == "__main__":  # local development server only; containers use gunicorn
    logging.basicConfig(level=logging.INFO)
    create_app().run(host=os.environ.get("API_HOST", "127.0.0.1"),
                     port=int(os.environ.get("API_PORT", "8082")))
