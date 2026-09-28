"""Process-wide services shared by the API and the worker."""

from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import Engine

from idprivacy.config import Settings, get_settings
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.crypto import FieldCipher, KeyProvider, build_key_provider
from idprivacy.platform.db import make_engine


@dataclass(frozen=True)
class Services:
    settings: Settings
    engine: Engine
    keys: KeyProvider
    cipher: FieldCipher
    registry: PolicyRegistry


def build_services(settings: Settings) -> Services:
    assert settings.local_master_key is not None  # guaranteed by Settings validation
    keys = build_key_provider(settings.local_master_key.get_secret_value())
    return Services(
        settings,
        make_engine(settings.database_url_app.get_secret_value()),
        keys,
        FieldCipher(keys),
        PolicyRegistry(),
    )


@lru_cache
def services() -> Services:
    return build_services(get_settings())
