"""Runtime configuration.

Settings are loaded from environment variables prefixed ``IDP_``. Validation fails at
startup if a dev-only stand-in (mock OTP provider, local key provider, in-memory rate
limiter) is configured outside ``local``/``test``. See docs/open-decisions.md (D-1, D-3).
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "test", "staging", "production"]
DEV_ENVIRONMENTS: frozenset[str] = frozenset({"local", "test"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDP_", extra="ignore")

    env: Environment = "local"

    # Database: one role per trust level (ADR-0002, ADR-0004).
    database_url_app: SecretStr
    database_url_relay: SecretStr | None = None

    redis_url: str = "redis://redis:6379/0"

    # Staff OIDC resource server (ADR-0003). Production IdP is decision D-1.
    oidc_issuer: str
    oidc_audience: str = "idprivacy-api"
    oidc_jwks_url: str
    oidc_algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])

    # Stand-in providers. Production choices are open decisions.
    otp_provider: Literal["mock"] = "mock"
    notification_provider: Literal["mock"] = "mock"
    # Connector credentials are resolved by reference (open decision D-5).
    connector_credential_source: Literal["env"] = "env"
    key_provider: Literal["local"] = "local"
    local_master_key: SecretStr | None = None

    # Evidence object storage (ADR-0007).
    s3_endpoint_url: str | None = None
    s3_bucket: str = "idprivacy-evidence"
    s3_access_key_id: SecretStr | None = None
    s3_secret_access_key: SecretStr | None = None

    # Service credential the web BFF presents on public (Data Principal) routes (ADR-0003).
    # A pre-shared secret for the MVP; production should use mTLS between BFF and API.
    bff_shared_secret: SecretStr = Field(min_length=32)

    # Public-intake hardening (threat model T-02, T-17).
    max_body_bytes: int = 64 * 1024
    rate_limiter: Literal["redis", "memory"] = "redis"
    otp_ttl_seconds: int = 600
    otp_max_attempts: int = 5
    otp_max_resends: int = 3
    otp_resend_interval_seconds: int = 30
    dp_session_idle_seconds: int = 1800
    dp_session_max_seconds: int = 86400

    # Fulfilment (M6): attempts per destructive task before it fails permanently.
    fulfilment_max_attempts: int = 5

    @model_validator(mode="after")
    def _refuse_dev_stand_ins_outside_dev(self) -> "Settings":
        errors: list[str] = []
        if self.env not in DEV_ENVIRONMENTS:
            if self.otp_provider == "mock":
                errors.append("mock OTP provider is only permitted in local/test")
            if self.notification_provider == "mock":
                errors.append("mock notification provider is only permitted in local/test")
            if self.key_provider == "local":
                errors.append("local key provider is only permitted in local/test")
            if self.connector_credential_source == "env":
                errors.append("env connector secrets are only permitted in local/test")
        allowed = {"RS256", "RS384", "RS512", "ES256", "ES384", "PS256"}
        if not self.oidc_algorithms or set(self.oidc_algorithms) - allowed:
            errors.append("oidc_algorithms must be a non-empty subset of asymmetric algorithms")
        if self.env not in DEV_ENVIRONMENTS and self.rate_limiter == "memory":
            errors.append("in-memory rate limiter is only permitted in local/test")
        if self.key_provider == "local" and self.local_master_key is None:
            errors.append("local_master_key is required for the local key provider")
        if errors:
            raise ValueError("; ".join(errors))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
