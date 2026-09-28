"""Build connector clients from tenant configuration."""

from idprivacy_connector_sdk import Connector, HttpConnector

from idprivacy.platform import secrets
from idprivacy.platform.models import ConnectorConfig


def build_connector(config: ConnectorConfig) -> Connector:
    if config.kind != "http_v1":
        raise ValueError(f"unsupported connector kind {config.kind!r}")
    return HttpConnector(config.base_url, secrets.resolve(config.credential_ref))
