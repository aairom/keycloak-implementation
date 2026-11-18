"""Static checks on the Keycloak realm file and Docker/compose configuration (no containers needed)."""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REALM = json.loads((ROOT / "keycloak/realm/demo-realm.json").read_text())


def client(client_id):
    return next(c for c in REALM["clients"] if c["clientId"] == client_id)


def test_realm_has_users_roles_groups_and_clients():
    assert {u["username"] for u in REALM["users"]} == {"alice", "bob", "service-account-demo-service"}
    assert {r["name"] for r in REALM["roles"]["realm"]} == {"app-user", "app-admin", "app-service"}
    assert {g["name"] for g in REALM["groups"]} == {"employees", "managers"}
    assert {c["clientId"] for c in REALM["clients"]} == {"demo-cli", "demo-webapp", "demo-api", "demo-service"}


def test_app_admin_is_composite_of_app_user():
    admin = next(r for r in REALM["roles"]["realm"] if r["name"] == "app-admin")
    assert admin["composites"]["realm"] == ["app-user"]


def test_no_clear_text_secrets_in_realm_file():
    """Every credential must be an ${ENV} placeholder, never a literal."""
    for u in (u for u in REALM["users"] if "credentials" in u or "serviceAccountClientId" not in u):
        assert re.fullmatch(r"\$\{[A-Z_]+\}", u["credentials"][0]["value"])
    for cid in ("demo-webapp", "demo-api", "demo-service"):
        assert re.fullmatch(r"\$\{[A-Z_]+\}", client(cid)["secret"])


def test_webapp_client_is_confidential_code_flow_with_pkce():
    c = client("demo-webapp")
    assert c["publicClient"] is False and c["standardFlowEnabled"] is True
    assert c["implicitFlowEnabled"] is False and c["directAccessGrantsEnabled"] is False
    assert c["attributes"]["pkce.code.challenge.method"] == "S256"
    assert c["redirectUris"] == ["${WEBAPP_PUBLIC_URL}/callback"]  # exact URI, no wildcard


def test_api_client_has_consistent_authorization_model():
    az = client("demo-api")["authorizationSettings"]
    resources = {r["name"]: {s["name"] for s in r["scopes"]} for r in az["resources"]}
    assert resources == {"reports": {"read", "write"}, "admin-panel": {"access"}, "service-data": {"read"}}
    policies = {p["name"] for p in az["policies"]}
    for p in az["policies"]:
        if p["type"] == "scope":
            for ref in json.loads(p["config"]["applyPolicies"]):
                assert ref in policies
            for res in json.loads(p["config"]["resources"]):
                assert res in resources
            for sc in json.loads(p["config"]["scopes"]):
                assert any(sc in s for s in resources.values())
    assert az["policyEnforcementMode"] == "ENFORCING"


def test_service_client_uses_client_credentials_only():
    c = client("demo-service")
    assert c["serviceAccountsEnabled"] is True and c["publicClient"] is False
    assert not (c["standardFlowEnabled"] or c["implicitFlowEnabled"] or c["directAccessGrantsEnabled"])
    sa = next(u for u in REALM["users"] if u.get("serviceAccountClientId") == "demo-service")
    assert sa["realmRoles"] == ["app-service"]


def test_audience_mapper_present_on_token_issuing_clients():
    for cid in ("demo-webapp", "demo-cli", "demo-service"):
        mappers = {m["name"]: m for m in client(cid)["protocolMappers"]}
        assert mappers["demo-api-audience"]["config"]["included.client.audience"] == "demo-api"


def test_realm_security_settings():
    assert REALM["bruteForceProtected"] is True
    assert REALM["sslRequired"] == "external"
    assert "length(" in REALM["passwordPolicy"]


def test_theme_files_exist():
    assert (ROOT / "keycloak/themes/demo/login/theme.properties").read_text().count("parent=keycloak.v2") == 1
    assert (ROOT / "keycloak/themes/demo/login/resources/css/demo.css").is_file()


def _env_vars(path):
    return set(re.findall(r"^([A-Z][A-Z0-9_]*)=", (ROOT / path).read_text(), re.M))


def test_every_compose_variable_is_documented_in_env_example():
    documented = _env_vars(".env.example")
    for name in ("docker-compose.yml", "docker-compose.prod.yml"):
        used = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", (ROOT / name).read_text()))
        assert used <= documented, f"{name}: undocumented {used - documented}"


def test_every_realm_placeholder_is_passed_to_keycloak_container():
    placeholders = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)\}", (ROOT / "keycloak/realm/demo-realm.json").read_text()))
    compose = (ROOT / "docker-compose.yml").read_text()
    for p in placeholders:
        assert re.search(rf"^\s+{p}:", compose, re.M), f"{p} not passed to the keycloak service"


def test_env_example_has_no_real_secrets():
    for line in (ROOT / ".env.example").read_text().splitlines():
        if re.match(r"[A-Z_]*(PASSWORD|SECRET)=", line):
            assert "changeme" in line


@pytest.mark.parametrize("path", ["keycloak/Dockerfile", "api/Dockerfile", "webapp/Dockerfile"])
def test_dockerfiles_are_multistage_non_root_and_pinned(path):
    text = (ROOT / path).read_text()
    assert len(re.findall(r"^FROM ", text, re.M)) == 2
    assert re.search(r"^USER (?!root)\S+", text, re.M)
    assert ":latest" not in text


def test_scripts_are_executable():
    for s in (ROOT / "scripts").glob("*.sh"):
        assert s.stat().st_mode & 0o111, f"{s.name} is not executable"
