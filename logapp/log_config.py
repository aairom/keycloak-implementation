"""Configuration of the log dashboard. Everything comes from environment variables (see ``.env.example``)."""
from __future__ import annotations

from dataclasses import dataclass

REQUIRED = ("OIDC_DISCOVERY_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "LOGAPP_SESSION_SECRET",
            "LOGAPP_PUBLIC_URL", "API_BASE_URL", "LOGAPP_DATABASE_URL", "SERVICE_CLIENT_SECRET")


def _int(env, name: str, default: int, minimum: int = 1) -> int:
    raw = env.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}, got {value}")
    return value


@dataclass(frozen=True)
class Config:
    discovery_url: str
    client_id: str
    client_secret: str
    session_secret: str
    public_url: str
    api_base_url: str
    database_url: str
    service_client_id: str
    service_client_secret: str
    admin_role: str = "app-admin"
    sync_interval: int = 10        # seconds between Keycloak event pulls
    expiry_warn: int = 60          # warn when the access token has this many seconds left
    page_size: int = 25            # rows per dashboard page
    idle_minutes: int = 30         # a session unseen for this long is not "active"
    trust_proxy: bool = False      # honour X-Forwarded-* from the reverse proxy (online deployment)

    @classmethod
    def from_env(cls, env) -> "Config":
        missing = [k for k in REQUIRED if not env.get(k)]
        if missing:
            raise RuntimeError(f"missing environment variables: {', '.join(missing)}")
        return cls(
            discovery_url=env["OIDC_DISCOVERY_URL"],
            client_id=env["OIDC_CLIENT_ID"],
            client_secret=env["OIDC_CLIENT_SECRET"],
            session_secret=env["LOGAPP_SESSION_SECRET"],
            public_url=env["LOGAPP_PUBLIC_URL"].rstrip("/"),
            api_base_url=env["API_BASE_URL"].rstrip("/"),
            database_url=env["LOGAPP_DATABASE_URL"],
            service_client_id=env.get("SERVICE_CLIENT_ID") or "demo-service",
            service_client_secret=env["SERVICE_CLIENT_SECRET"],
            admin_role=env.get("LOGAPP_ADMIN_ROLE") or "app-admin",
            sync_interval=_int(env, "LOGAPP_SYNC_INTERVAL", 10),
            expiry_warn=_int(env, "LOGAPP_EXPIRY_WARN_SECONDS", 60),
            page_size=_int(env, "LOGAPP_PAGE_SIZE", 25),
            idle_minutes=_int(env, "LOGAPP_IDLE_MINUTES", 30),
            trust_proxy=str(env.get("LOGAPP_TRUST_PROXY", "")).lower() in ("1", "true", "yes"),
        )

    @property
    def realm(self) -> str:
        """Realm name parsed from the discovery URL ``.../realms/<realm>/.well-known/...``."""
        return self.discovery_url.split("/realms/", 1)[1].split("/", 1)[0]

    @property
    def token_url(self) -> str:
        """Token endpoint on the same (internal) host as the discovery URL."""
        return self.discovery_url.split("/.well-known/", 1)[0] + "/protocol/openid-connect/token"

    @property
    def admin_api_base(self) -> str:
        """Keycloak Admin REST base for the realm, on the same (internal) host as the discovery URL."""
        return f"{self.discovery_url.split('/realms/', 1)[0]}/admin/realms/{self.realm}"

    @property
    def secure_cookies(self) -> bool:
        return self.public_url.startswith("https://")
