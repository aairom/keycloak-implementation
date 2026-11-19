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
    assert {u["username"] for u in REALM["users"]} == {"alice", "bob", "service-account-demo-service",
                                                       "service-account-demo-logapp"}
    assert {r["name"] for r in REALM["roles"]["realm"]} == {"app-user", "app-admin", "app-service"}
    assert {g["name"] for g in REALM["groups"]} == {"employees", "managers"}
    assert {c["clientId"] for c in REALM["clients"]} == {"demo-cli", "demo-webapp", "demo-api", "demo-service",
                                                         "demo-logapp"}


def test_app_admin_is_composite_of_app_user():
    admin = next(r for r in REALM["roles"]["realm"] if r["name"] == "app-admin")
    assert admin["composites"]["realm"] == ["app-user"]


def test_no_clear_text_secrets_in_realm_file():
    """Every credential must be an ${ENV} placeholder, never a literal."""
    for u in (u for u in REALM["users"] if "credentials" in u or "serviceAccountClientId" not in u):
        assert re.fullmatch(r"\$\{[A-Z_]+\}", u["credentials"][0]["value"])
    for cid in ("demo-webapp", "demo-api", "demo-service", "demo-logapp"):
        assert re.fullmatch(r"\$\{[A-Z_]+\}", client(cid)["secret"])


def test_webapp_client_is_confidential_code_flow_with_pkce():
    c = client("demo-webapp")
    assert c["publicClient"] is False and c["standardFlowEnabled"] is True
    assert c["implicitFlowEnabled"] is False and c["directAccessGrantsEnabled"] is False
    assert c["attributes"]["pkce.code.challenge.method"] == "S256"
    assert c["redirectUris"] == ["${WEBAPP_PUBLIC_URL}/callback"]  # exact URI, no wildcard


def test_logapp_client_is_confidential_code_flow_with_pkce_and_event_reader():
    c = client("demo-logapp")
    assert c["publicClient"] is False and c["standardFlowEnabled"] is True and c["serviceAccountsEnabled"] is True
    assert c["implicitFlowEnabled"] is False and c["directAccessGrantsEnabled"] is False
    assert c["attributes"]["pkce.code.challenge.method"] == "S256"
    assert c["redirectUris"] == ["${LOGAPP_PUBLIC_URL}/callback"]  # exact URI, no wildcard
    # the admin API scope is optional: only the event-sync token request asks for it, user tokens do not carry it
    # (listing optional scopes replaces the realm defaults, so the defaults must be listed too)
    assert "kc-admin-api" in c["optionalClientScopes"] and "kc-admin-api" not in c["defaultClientScopes"]
    assert {"profile", "email", "roles"} <= set(c["defaultClientScopes"])
    sa = next(u for u in REALM["users"] if u.get("serviceAccountClientId") == "demo-logapp")
    # least privilege: it may read events and nothing else in the realm-management client
    assert sa["clientRoles"] == {"realm-management": ["view-events"]} and "realmRoles" not in sa


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
    for cid in ("demo-webapp", "demo-cli", "demo-service", "demo-logapp"):
        mappers = {m["name"]: m for m in client(cid)["protocolMappers"]}
        assert mappers["demo-api-audience"]["config"]["included.client.audience"] == "demo-api"


def test_realm_security_settings():
    assert REALM["bruteForceProtected"] is True
    assert REALM["sslRequired"] == "external"
    assert "length(" in REALM["passwordPolicy"]


def test_keycloak_events_cover_what_the_dashboard_shows():
    """REFRESH_TOKEN is not stored by default in Keycloak, so the realm must list the event types explicitly."""
    assert REALM["eventsEnabled"] is True and REALM["adminEventsEnabled"] is True
    enabled = set(REALM["enabledEventTypes"])
    assert {"LOGIN", "LOGIN_ERROR", "LOGOUT", "REFRESH_TOKEN", "REFRESH_TOKEN_ERROR", "CLIENT_LOGIN",
            "CLIENT_LOGIN_ERROR", "CODE_TO_TOKEN"} <= enabled
    assert len(enabled) == len(REALM["enabledEventTypes"])  # no duplicates


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


@pytest.mark.parametrize("path", ["keycloak/Dockerfile", "api/Dockerfile", "webapp/Dockerfile", "logapp/Dockerfile"])
def test_dockerfiles_are_multistage_non_root_and_pinned(path):
    text = (ROOT / path).read_text()
    assert len(re.findall(r"^FROM ", text, re.M)) == 2
    assert re.search(r"^USER (?!root)\S+", text, re.M)
    assert ":latest" not in text


def test_logapp_container_runs_one_worker_and_ships_every_module():
    """Tokens live in process memory, so more than one worker would break sessions; all modules must be copied."""
    text = (ROOT / "logapp/Dockerfile").read_text()
    assert '"--workers", "1"' in text
    copied = re.search(r"^COPY (\S.*?\.py) \./", text, re.M).group(1).split()
    on_disk = sorted(p.name for p in (ROOT / "logapp").glob("*.py"))
    assert sorted(copied) == on_disk


def test_logapp_is_routed_by_caddy_and_depends_on_database_schema_not_new_infrastructure():
    assert "{$LOGAPP_PUBLIC_HOST}" in (ROOT / "deploy/Caddyfile").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "@postgres:5432/${POSTGRES_DB}" in compose  # reuses the existing PostgreSQL server


def test_scripts_are_executable():
    for s in (ROOT / "scripts").glob("*.sh"):
        assert s.stat().st_mode & 0o111, f"{s.name} is not executable"


# ---------------------------------------------------------------------------------------------------
# keycloak_connector.config.KeycloakConfig (the reusable connector package in connector/)
# ---------------------------------------------------------------------------------------------------
from keycloak_connector import ConfigError, KeycloakConfig  # noqa: E402

BASE = dict(server_url="https://auth.example.com/", realm="r", client_id="c", redirect_uri="https://app.example.com/cb")


def test_normalises_server_url_and_derives_endpoints():
    cfg = KeycloakConfig(**BASE)
    assert cfg.server_url == "https://auth.example.com"
    assert cfg.issuer == "https://auth.example.com/realms/r"
    assert cfg.discovery_url.endswith("/realms/r/.well-known/openid-configuration")
    assert cfg.is_confidential is False


def test_confidential_when_secret_given_and_empty_secret_means_public():
    assert KeycloakConfig(client_secret="x", **BASE).is_confidential
    assert KeycloakConfig(client_secret="", **BASE).client_secret is None


def test_repr_never_shows_the_secret():
    secret = "".join(["top", "-", "hidden"])
    text = repr(KeycloakConfig(client_secret=secret, **BASE))
    assert secret not in text and "client_secret=<set>" in text
    assert "client_secret=<none>" in repr(KeycloakConfig(**BASE))


@pytest.mark.parametrize("field", ["server_url", "realm", "client_id", "redirect_uri"])
def test_missing_required_field(field):
    with pytest.raises(ConfigError, match=field):
        KeycloakConfig(**{**BASE, field: ""})


def test_all_problems_reported_together():
    with pytest.raises(ConfigError) as info:
        KeycloakConfig(server_url="ftp://x", realm="r", client_id="c", redirect_uri="/relative",
                       post_logout_redirect_uri="nope", scopes=("profile",), timeout=0, retries=-1,
                       allowed_algs=("none",))
    msg = str(info.value)
    for part in ("server_url must be", "redirect_uri must be", "post_logout_redirect_uri", "openid", "timeout",
                 "retries", "allowed_algs"):
        assert part in msg


def test_empty_algorithm_list_rejected():
    with pytest.raises(ConfigError, match="allowed_algs"):
        KeycloakConfig(allowed_algs=(), **BASE)


def test_from_env_reads_every_variable():
    env = {"KEYCLOAK_SERVER_URL": "https://auth.example.com", "KEYCLOAK_REALM": "r", "KEYCLOAK_CLIENT_ID": "c",
           "KEYCLOAK_CLIENT_SECRET": "s", "KEYCLOAK_REDIRECT_URI": "https://app.example.com/cb",
           "KEYCLOAK_SCOPES": "openid,email", "KEYCLOAK_POST_LOGOUT_REDIRECT_URI": "https://app.example.com/",
           "KEYCLOAK_AUDIENCE": "api", "KEYCLOAK_USE_PKCE": "false", "KEYCLOAK_TIMEOUT": "3.5",
           "KEYCLOAK_RETRIES": "4", "KEYCLOAK_LEEWAY": "20", "KEYCLOAK_REFRESH_MARGIN": "60",
           "KEYCLOAK_JWKS_TTL": "99"}
    cfg = KeycloakConfig.from_env(env)
    assert cfg.scopes == ("openid", "email") and cfg.audience == "api" and cfg.use_pkce is False
    assert (cfg.timeout, cfg.retries, cfg.leeway, cfg.refresh_margin, cfg.jwks_ttl) == (3.5, 4, 20, 60, 99)
    assert cfg.verify is True


def test_from_env_tls_options():
    base = {"KEYCLOAK_SERVER_URL": "https://a.example.com", "KEYCLOAK_REALM": "r", "KEYCLOAK_CLIENT_ID": "c",
            "KEYCLOAK_REDIRECT_URI": "https://b.example.com/cb"}
    assert KeycloakConfig.from_env({**base, "KEYCLOAK_VERIFY_TLS": "false"}).verify is False
    assert KeycloakConfig.from_env({**base, "KEYCLOAK_CA_BUNDLE": "/etc/ca.pem"}).verify == "/etc/ca.pem"


def test_from_env_custom_prefix_and_process_environment(monkeypatch):
    monkeypatch.setenv("MYAPP_KC_SERVER_URL", "https://auth.example.com")
    monkeypatch.setenv("MYAPP_KC_REALM", "r")
    monkeypatch.setenv("MYAPP_KC_CLIENT_ID", "c")
    monkeypatch.setenv("MYAPP_KC_REDIRECT_URI", "https://app.example.com/cb")
    assert KeycloakConfig.from_env(prefix="MYAPP_KC_").realm == "r"


def test_from_env_reports_bad_numbers_and_missing_values():
    env = {"KEYCLOAK_SERVER_URL": "https://a.example.com", "KEYCLOAK_REALM": "r", "KEYCLOAK_CLIENT_ID": "c",
           "KEYCLOAK_REDIRECT_URI": "https://b.example.com/cb", "KEYCLOAK_TIMEOUT": "soon"}
    with pytest.raises(ConfigError, match="TIMEOUT"):
        KeycloakConfig.from_env(env)
    with pytest.raises(ConfigError, match="server_url"):
        KeycloakConfig.from_env({})
