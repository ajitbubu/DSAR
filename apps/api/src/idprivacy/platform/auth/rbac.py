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
    POLICY_READ = "policy:read"
    CASE_READ = "case:read"
    # Referenced by policy-pack workflow transitions (enforced from M4/M5 onward).
    CASE_REVIEW = "case:review"
    CASE_APPROVE = "case:approve"
    CASE_CLOSE = "case:close"
    LEGAL_HOLD_READ = "legal_hold:read"
    LEGAL_HOLD_MANAGE = "legal_hold:manage"
    # Access requests: reading exported personal data, and maintaining the register.
    DISCLOSURE_READ = "disclosure:read"
    REGISTER_MANAGE = "register:manage"


_BASE = frozenset({Permission.SELF_READ, Permission.POLICY_READ})

ROLE_PERMISSIONS: dict[RoleCode, frozenset[Permission]] = {
    RoleCode.TENANT_ADMIN: _BASE
    | {Permission.LEGAL_HOLD_READ, Permission.LEGAL_HOLD_MANAGE, Permission.REGISTER_MANAGE},
    RoleCode.PRIVACY_ANALYST: _BASE
    | {
        Permission.CASE_READ,
        Permission.CASE_REVIEW,
        Permission.CASE_CLOSE,
        Permission.DISCLOSURE_READ,
        Permission.LEGAL_HOLD_READ,
        Permission.LEGAL_HOLD_MANAGE,
    },
    # Approvers only approve; maker-checker separation is enforced again in M5.
    RoleCode.APPROVER: _BASE
    | {
        Permission.CASE_READ,
        Permission.CASE_APPROVE,
        Permission.DISCLOSURE_READ,
        Permission.LEGAL_HOLD_READ,
    },
    RoleCode.AUDITOR: _BASE
    | {Permission.CASE_READ, Permission.AUDIT_VERIFY, Permission.LEGAL_HOLD_READ},
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
