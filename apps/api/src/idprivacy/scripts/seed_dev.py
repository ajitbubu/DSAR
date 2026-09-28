"""Seed two dev tenants whose staff users match the Keycloak dev realm.

Local/test only. Runs as the migrator role (table owner, RLS-exempt) and is idempotent.
The subjects below are the fixed user ids in infra/compose/keycloak/idprivacy-realm.json.
"""

import os
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from idprivacy.config import DEV_ENVIRONMENTS
from idprivacy.domain.audit import service as audit
from idprivacy.platform.crypto import FieldCipher, build_key_provider
from idprivacy.platform.models import (
    AppUser,
    ConnectorConfig,
    ProcessingRegisterEntry,
    Role,
    Tenant,
    TenantPolicyPack,
    UserRole,
)

ISSUER = os.environ.get("IDP_OIDC_ISSUER", "http://localhost:8080/realms/idprivacy")

TENANTS = {
    "acme": ("Acme Retail (dev)", uuid.UUID("a0000000-0000-4000-8000-000000000001")),
    "globex": ("Globex Finance (dev)", uuid.UUID("b0000000-0000-4000-8000-000000000001")),
}
# slug -> [(keycloak subject, email, display name, roles)]
USERS = {
    "acme": [
        (
            "11111111-1111-4111-8111-000000000001",
            "analyst@acme.example.test",
            "Acme Analyst",
            ["PRIVACY_ANALYST"],
        ),
        (
            "11111111-1111-4111-8111-000000000002",
            "approver@acme.example.test",
            "Acme Approver",
            ["APPROVER"],
        ),
        (
            "11111111-1111-4111-8111-000000000003",
            "auditor@acme.example.test",
            "Acme Auditor",
            ["AUDITOR"],
        ),
        (
            "11111111-1111-4111-8111-000000000004",
            "admin@acme.example.test",
            "Acme Admin",
            ["TENANT_ADMIN"],
        ),
    ],
    "globex": [
        (
            "22222222-2222-4222-8222-000000000001",
            "analyst@globex.example.test",
            "Globex Analyst",
            ["PRIVACY_ANALYST"],
        ),
        (
            "22222222-2222-4222-8222-000000000003",
            "auditor@globex.example.test",
            "Globex Auditor",
            ["AUDITOR"],
        ),
    ],
}
ROLE_CODES = ("TENANT_ADMIN", "PRIVACY_ANALYST", "APPROVER", "AUDITOR")
# Both dev tenants process data in India and enable the DPDP pack.
DEV_REGION = "IN"
DEV_PACKS = [("DPDP", "1.1.0")]  # new cases use the latest; old ones stay pinned
MOCK_BASE = os.environ.get("IDP_MOCK_CONNECTORS_URL", "http://mock-connectors:8100")
DEV_CONNECTORS = [("mock-crm", "CRM (mock)", "crm"), ("mock-docs", "Document store (mock)", "docs")]
# Illustrative processing-register entries (decision D-27), so access cases can be submitted.
DEV_REGISTER = {
    "mock-crm": (
        ["Order fulfilment and customer support", "Billing"],
        [{"name": "Example Payments Pvt Ltd", "kind": "PROCESSOR"}],
    ),
    "mock-docs": (["Handling complaints and warranty claims"], []),
}


def seed(session: Session, cipher: FieldCipher) -> None:
    for slug, (name, tenant_id) in TENANTS.items():
        tenant = session.get(Tenant, tenant_id)
        if tenant is None:
            tenant = Tenant(id=tenant_id, slug=slug, name=name, status="ACTIVE")
            session.add(tenant)
        tenant.data_region = DEV_REGION
        session.flush()
        for priority, (code, version) in enumerate(DEV_PACKS):
            enabled = session.get(TenantPolicyPack, (tenant_id, code))
            if enabled is None:
                session.add(
                    TenantPolicyPack(
                        tenant_id=tenant_id,
                        pack_code=code,
                        pack_version=version,
                        priority=priority,
                        enabled=True,
                    )
                )
            else:
                enabled.pack_version = version
        for connector_id, display, system in DEV_CONNECTORS:
            exists = session.execute(
                select(ConnectorConfig).where(
                    ConnectorConfig.tenant_id == tenant_id,
                    ConnectorConfig.connector_id == connector_id,
                )
            ).scalar_one_or_none()
            if exists is None:
                session.add(
                    ConnectorConfig(
                        tenant_id=tenant_id,
                        connector_id=connector_id,
                        display_name=display,
                        kind="http_v1",
                        base_url=f"{MOCK_BASE}/{slug}/{system}",
                        credential_ref="env:IDP_CONNECTOR_TOKEN_MOCK",
                        enabled=True,
                    )
                )
        session.flush()
        for connector_id, (purposes, recipients) in DEV_REGISTER.items():
            # Explicit tenant filter: the seed runs as the RLS-exempt migrator.
            if (
                session.execute(
                    select(ProcessingRegisterEntry.id).where(
                        ProcessingRegisterEntry.tenant_id == tenant_id,
                        ProcessingRegisterEntry.connector_id == connector_id,
                    )
                ).first()
                is None
            ):
                session.add(
                    ProcessingRegisterEntry(
                        tenant_id=tenant_id,
                        connector_id=connector_id,
                        purposes=purposes,
                        recipients=recipients,
                    )
                )
        roles: dict[str, uuid.UUID] = {}
        for code in ROLE_CODES:
            role = session.execute(
                select(Role).where(Role.tenant_id == tenant_id, Role.code == code)
            ).scalar_one_or_none()
            if role is None:
                role = Role(tenant_id=tenant_id, code=code)
                session.add(role)
                session.flush()
            roles[code] = role.id
        for subject, email, display, role_codes in USERS[slug]:
            user = session.execute(
                select(AppUser).where(AppUser.idp_issuer == ISSUER, AppUser.idp_subject == subject)
            ).scalar_one_or_none()
            if user is not None:
                continue
            user = AppUser(
                tenant_id=tenant_id,
                idp_issuer=ISSUER,
                idp_subject=subject,
                status="ACTIVE",
                display_name=display,
                enc_email=cipher.encrypt(tenant_id, "app_user.email", email),
            )
            session.add(user)
            session.flush()
            for code in role_codes:
                session.add(UserRole(tenant_id=tenant_id, user_id=user.id, role_id=roles[code]))
            audit.append(
                session,
                tenant_id=tenant_id,
                actor_type="SYSTEM",
                actor_ref="system:seed_dev",
                action="user.provisioned",
                object_type="app_user",
                object_id=user.id,
                details={"roles": role_codes},
            )


def main() -> None:
    if os.environ.get("IDP_ENV", "local") not in DEV_ENVIRONMENTS:
        raise SystemExit("seed_dev is only permitted in local/test")
    cipher = FieldCipher(build_key_provider(os.environ["IDP_LOCAL_MASTER_KEY"]))
    engine = create_engine(os.environ["IDP_DATABASE_URL_MIGRATOR"])
    with Session(engine) as session, session.begin():
        seed(session, cipher)
    print("seeded dev tenants:", ", ".join(TENANTS))  # noqa: T201


if __name__ == "__main__":
    main()
