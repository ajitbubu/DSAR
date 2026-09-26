"""Roles, permissions and route-level declarations.

Every route must declare either ``Requires(<permission>)`` or ``Public()`` as a
dependency. ``tests/test_route_inventory.py`` fails the build if a route has neither.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID


class RoleCode(StrEnum):
    TENANT_ADMIN = "TENANT_ADMIN"
    PRIVACY_ANALYST = "PRIVACY_ANALYST"
    APPROVER = "APPROVER"
    AUDITOR = "AUDITOR"


class Permission(StrEnum):
    SELF_READ = "self:read"
    AUDIT_VERIFY = "audit:verify"


ROLE_PERMISSIONS: dict[RoleCode, frozenset[Permission]] = {
    RoleCode.TENANT_ADMIN: frozenset({Permission.SELF_READ}),
    RoleCode.PRIVACY_ANALYST: frozenset({Permission.SELF_READ}),
    RoleCode.APPROVER: frozenset({Permission.SELF_READ}),
    RoleCode.AUDITOR: frozenset({Permission.SELF_READ, Permission.AUDIT_VERIFY}),
}


@dataclass(frozen=True)
class StaffPrincipal:
    user_id: UUID
    tenant_id: UUID
    subject: str
    roles: frozenset[RoleCode] = field(default_factory=frozenset)

    @property
    def permissions(self) -> frozenset[Permission]:
        perms: set[Permission] = set()
        for role in self.roles:
            perms |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(perms)

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions
