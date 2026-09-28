"""Process-wide services shared by the API and the worker."""

from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import Engine

from idprivacy.config import Settings, get_settings
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.crypto import FieldCipher, KeyProvider, build_key_provider
from idprivacy.platform.db import make_engine
from idprivacy.platform.storage import BlobStore, S3BlobStore


@dataclass(frozen=True)
class Services:
    settings: Settings
    engine: Engine
    keys: KeyProvider
    cipher: FieldCipher
    registry: PolicyRegistry
    blob_store: BlobStore


def build_services(settings: Settings, blob_store: BlobStore | None = None) -> Services:
    assert settings.local_master_key is not None  # guaranteed by Settings validation
    keys = build_key_provider(settings.local_master_key.get_secret_value())
    store = blob_store or S3BlobStore(
        endpoint_url=settings.s3_endpoint_url,
        bucket=settings.s3_bucket,
        access_key=settings.s3_access_key_id.get_secret_value()
        if settings.s3_access_key_id
        else None,
        secret_key=settings.s3_secret_access_key.get_secret_value()
        if settings.s3_secret_access_key
        else None,
    )
    return Services(
        settings,
        make_engine(settings.database_url_app.get_secret_value()),
        keys,
        FieldCipher(keys),
        PolicyRegistry(),
        store,
    )


@lru_cache
def services() -> Services:
    return build_services(get_settings())
