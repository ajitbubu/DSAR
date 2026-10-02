"""Create each tenant's Vault Transit keys (decision D-3). Safe to re-run.

Run once after adding a tenant, before it takes requests. It lists tenants with the
migrator role, since the tenant table is RLS-scoped.
"""

import os
from uuid import UUID

from sqlalchemy import create_engine, text

from idprivacy.config import get_settings
from idprivacy.platform.crypto import VaultTransitKeyProvider
from idprivacy.runtime import build_keys


def main() -> None:
    keys = build_keys(get_settings())
    if not isinstance(keys, VaultTransitKeyProvider):
        raise SystemExit("IDP_KEY_PROVIDER is not 'vault'; nothing to provision")
    lister = create_engine(os.environ["IDP_DATABASE_URL_MIGRATOR"])
    with lister.connect() as conn:
        rows: list[object] = list(conn.execute(text("SELECT id FROM tenant")).scalars())
    for t in rows:
        keys.provision(UUID(str(t)))
    print(f"provisioned keys for {len(rows)} tenant(s)")  # noqa: T201


if __name__ == "__main__":
    main()
