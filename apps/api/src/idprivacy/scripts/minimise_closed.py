"""Shred requester identifiers of cases closed longer than their grace period (D-12).

Run on a schedule (e.g. daily) as a one-off job. It lists tenants with the migrator
role, since the tenant table is RLS-scoped, then does all the work per tenant as the
application role, so each tenant's minimisation stays inside its own RLS scope.
"""

import os
from uuid import UUID

from sqlalchemy import create_engine, text

from idprivacy.config import get_settings
from idprivacy.domain.minimisation.service import minimise_due
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.runtime import build_services


def main() -> None:
    svc = build_services(get_settings())
    lister = create_engine(os.environ["IDP_DATABASE_URL_MIGRATOR"])
    with lister.connect() as conn:
        rows: list[object] = list(conn.execute(text("SELECT id FROM tenant")).scalars())
    tenants: list[UUID] = [UUID(str(t)) for t in rows]
    done = held = 0
    for tenant_id in tenants:
        with tenant_session(svc.engine, TenantContext(tenant_id)) as session:
            d, h = minimise_due(session, registry=svc.registry, store=svc.blob_store)
        done, held = done + d, held + h
    print(f"minimised {done} case(s); {held} held back by a legal hold")  # noqa: T201


if __name__ == "__main__":
    main()
