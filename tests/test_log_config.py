"""Unit tests for logapp/log_config.py."""
import pytest

from log_config import REQUIRED, Config

ENV = {
    "OIDC_DISCOVERY_URL": "http://keycloak:8080/realms/demo/.well-known/openid-configuration",
    "OIDC_CLIENT_ID": "demo-logapp", "OIDC_CLIENT_SECRET": "cs", "LOGAPP_SESSION_SECRET": "ss",
    "LOGAPP_PUBLIC_URL": "http://localhost:8083/", "API_BASE_URL": "http://api:8082/",
    "LOGAPP_DATABASE_URL": "sqlite:///:memory:", "SERVICE_CLIENT_SECRET": "svc",
}


def test_defaults_and_normalisation():
    c = Config.from_env(ENV)
    assert c.public_url == "http://localhost:8083" and c.api_base_url == "http://api:8082"
    assert (c.sync_interval, c.expiry_warn, c.page_size, c.idle_minutes) == (10, 60, 25, 30)
    assert c.admin_role == "app-admin" and c.service_client_id == "demo-service" and c.trust_proxy is False
    assert c.secure_cookies is False


def test_derived_urls():
    c = Config.from_env(ENV)
    assert c.realm == "demo"
    assert c.token_url == "http://keycloak:8080/realms/demo/protocol/openid-connect/token"
    assert c.admin_api_base == "http://keycloak:8080/admin/realms/demo"


def test_overrides():
    c = Config.from_env({**ENV, "LOGAPP_PUBLIC_URL": "https://logs.example.com", "LOGAPP_PAGE_SIZE": "50",
                         "LOGAPP_ADMIN_ROLE": "ops", "LOGAPP_TRUST_PROXY": "TRUE", "SERVICE_CLIENT_ID": "svc-x"})
    assert (c.page_size, c.admin_role, c.trust_proxy, c.service_client_id) == (50, "ops", True, "svc-x")
    assert c.secure_cookies is True


@pytest.mark.parametrize("missing", REQUIRED)
def test_each_required_variable_is_enforced(missing):
    env = {k: v for k, v in ENV.items() if k != missing}
    with pytest.raises(RuntimeError, match=missing):
        Config.from_env(env)


@pytest.mark.parametrize("name,value", [("LOGAPP_PAGE_SIZE", "abc"), ("LOGAPP_PAGE_SIZE", "0"),
                                        ("LOGAPP_SYNC_INTERVAL", "-5")])
def test_invalid_numbers_are_rejected(name, value):
    with pytest.raises(RuntimeError, match=name):
        Config.from_env({**ENV, name: value})


def test_empty_optional_value_uses_default():
    assert Config.from_env({**ENV, "LOGAPP_PAGE_SIZE": "", "LOGAPP_ADMIN_ROLE": ""}).page_size == 25
    assert Config.from_env({**ENV, "LOGAPP_ADMIN_ROLE": ""}).admin_role == "app-admin"
