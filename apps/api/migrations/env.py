"""Alembic runs as ``idp_migrator``, the schema owner. The app never holds these credentials."""

import os

from alembic import context
from sqlalchemy import create_engine

from idprivacy.platform.models import Base

target_metadata = Base.metadata


def run_migrations_online() -> None:
    url = context.config.attributes.get("url") or os.environ["IDP_DATABASE_URL_MIGRATOR"]
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
