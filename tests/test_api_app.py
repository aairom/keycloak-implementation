"""Unit tests for api/api_app.py: HTTP behaviour of the protected endpoints."""
import pytest

from api_app import build_dependencies, create_app
from api_auth import PolicyDecisionClient, TokenValidator
from conftest import AUDIENCE, ISSUER


class FakePdp:
    """Policy decision point with a fixed allow-list of 'resource#scope' pairs per role."""
    RULES = {"app-user": {"reports#read"},
             "app-admin": {"reports#read", "reports#write", "admin-panel#access"},
             "app-service": {"service-data#read"}}

    def __init__(self):
        self.calls = []

    def is_permitted(self, token, resource, scope):
        import jwt
        roles = jwt.decode(token, options={"verify_signature": False})["realm_access"]["roles"]
        self.calls.append(f"{resource}#{scope}")
        return any(f"{resource}#{scope}" in self.RULES.get(r, ()) for r in roles)


@pytest.fixture
def pdp():
    return FakePdp()


@pytest.fixture
def client(jwks, pdp):
    validator = TokenValidator(ISSUER, AUDIENCE, jwks_client=jwks)
    return create_app(validator=validator, pdp=pdp).test_client()


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def user_token(make_token, *roles, **extra):
    return make_token(realm_access={"roles": list(roles)}, **extra)


def test_health_is_public(client):
    assert client.get("/api/health").get_json() == {"status": "UP"}


@pytest.mark.parametrize("method,path", [("get", "/api/me"), ("get", "/api/reports"),
                                          ("post", "/api/reports"), ("get", "/api/admin")])
def test_protected_endpoints_require_a_token(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"].startswith("Bearer")


def test_invalid_token_is_401(client):
    assert client.get("/api/reports", headers=auth("garbage")).status_code == 401


def test_me_returns_identity(client, make_token):
    body = client.get("/api/me", headers=auth(user_token(make_token, "app-user"))).get_json()
    assert body["username"] == "alice" and body["roles"] == ["app-user"] and body["groups"] == ["employees"]


def test_employee_can_read_reports(client, make_token):
    resp = client.get("/api/reports", headers=auth(user_token(make_token, "app-user")))
    assert resp.status_code == 200 and resp.get_json()["requested_by"] == "alice"


def test_employee_cannot_write_or_open_admin(client, make_token, pdp):
    h = auth(user_token(make_token, "app-user"))
    assert client.post("/api/reports", headers=h).status_code == 403
    assert client.get("/api/admin", headers=h).status_code == 403
    assert pdp.calls == ["reports#write", "admin-panel#access"]


def test_manager_can_do_everything(client, make_token):
    h = auth(user_token(make_token, "app-admin", preferred_username="bob"))
    assert client.get("/api/reports", headers=h).status_code == 200
    created = client.post("/api/reports", headers=h)
    assert created.status_code == 201 and created.get_json()["created_by"] == "bob"
    assert client.get("/api/admin", headers=h).status_code == 200


def test_unknown_route_is_json_404(client):
    resp = client.get("/api/nope")
    assert resp.status_code == 404 and resp.get_json()["error"] == "not_found"


def test_identity_provider_outage_is_503(jwks, make_token):
    class BrokenPdp:
        def is_permitted(self, *a):
            raise ConnectionError("keycloak down")
    app = create_app(TokenValidator(ISSUER, AUDIENCE, jwks_client=jwks), BrokenPdp())
    resp = app.test_client().get("/api/reports", headers=auth(user_token(make_token, "app-user")))
    assert resp.status_code == 503 and resp.get_json()["error"] == "upstream_unavailable"


def test_dependencies_are_built_lazily_from_env(monkeypatch):
    import api_app
    monkeypatch.setattr(api_app, "discover", lambda url: {"jwks_uri": "https://kc/certs",
                                                           "token_endpoint": "https://kc/token"})
    env = {"OIDC_DISCOVERY_URL": "https://kc/.well-known", "OIDC_ISSUER": ISSUER, "API_AUDIENCE": AUDIENCE}
    validator, pdp = build_dependencies(env)
    assert isinstance(validator, TokenValidator) and validator.issuer == ISSUER
    assert isinstance(pdp, PolicyDecisionClient) and pdp.token_endpoint == "https://kc/token"
    # create_app with env must not touch the network until the first protected request
    assert create_app(env=env).test_client().get("/api/health").status_code == 200


def test_service_endpoint_allows_only_the_service_role(client, make_token):
    svc = auth(user_token(make_token, "app-service", preferred_username="service-account-demo-service", azp="demo-service"))
    resp = client.get("/api/service/data", headers=svc)
    assert resp.status_code == 200
    assert resp.get_json()["caller"] == "service-account-demo-service" and resp.get_json()["client"] == "demo-service"
    for role in ("app-user", "app-admin"):
        assert client.get("/api/service/data", headers=auth(user_token(make_token, role))).status_code == 403
    assert client.get("/api/service/data").status_code == 401
    # and the service identity cannot use human endpoints
    assert client.get("/api/reports", headers=svc).status_code == 403
