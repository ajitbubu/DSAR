"""Published policy packs: publishing (migrator) and the runtime registry (app/worker)."""

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.domain.policy.loader import (
    LoadedPack,
    PackIntegrityError,
    canonical_hash,
    parse,
)
from idprivacy.domain.policy.model import PolicyPack
from idprivacy.platform.models import PolicyPackRow


def publish(session: Session, loaded: LoadedPack) -> PolicyPackRow:
    """Insert a pack version if new. Refuses to change an already-published version."""
    existing = session.execute(
        select(PolicyPackRow).where(
            PolicyPackRow.code == loaded.pack.code, PolicyPackRow.version == loaded.pack.version
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.content_sha256 != loaded.sha256:
            raise PackIntegrityError(
                f"{loaded.pack.ref} is already published with a different hash; "
                "published packs are immutable, so bump the version"
            )
        return existing
    row = PolicyPackRow(
        code=loaded.pack.code,
        version=loaded.pack.version,
        content_sha256=loaded.sha256,
        content=loaded.content,
        status="PUBLISHED",
        published_at=datetime.now(UTC),
    )
    session.add(row)
    session.flush()
    return row


@dataclass(frozen=True)
class PublishedPack:
    id: UUID
    pack: PolicyPack
    sha256: str


class PolicyRegistry:
    """Read-through cache of published packs. Each row is re-hashed before use."""

    def __init__(self) -> None:
        self._by_id: dict[UUID, PublishedPack] = {}
        self._lock = Lock()

    def _verify(self, row: PolicyPackRow) -> PublishedPack:
        if canonical_hash(row.content) != row.content_sha256:
            raise PackIntegrityError(f"{row.code}@{row.version}: stored content was altered")
        pack = parse(row.content)
        if (pack.code, pack.version) != (row.code, row.version):
            raise PackIntegrityError(f"{row.code}@{row.version}: identity mismatch")
        return PublishedPack(row.id, pack, row.content_sha256)

    def get(self, session: Session, code: str, version: str) -> PublishedPack | None:
        with self._lock:
            for cached in self._by_id.values():
                if (cached.pack.code, cached.pack.version) == (code, version):
                    return cached
        row = session.execute(
            select(PolicyPackRow).where(
                PolicyPackRow.code == code,
                PolicyPackRow.version == version,
                PolicyPackRow.status == "PUBLISHED",
            )
        ).scalar_one_or_none()
        return self._remember(row) if row else None

    def by_id(self, session: Session, pack_id: UUID) -> PublishedPack:
        with self._lock:
            if pack_id in self._by_id:
                return self._by_id[pack_id]
        row = session.get(PolicyPackRow, pack_id)
        if row is None:
            raise LookupError(pack_id)
        return self._remember(row)

    def all_published(self, session: Session) -> list[PublishedPack]:
        rows = session.execute(
            select(PolicyPackRow)
            .where(PolicyPackRow.status == "PUBLISHED")
            .order_by(PolicyPackRow.code, PolicyPackRow.version)
        ).scalars()
        return [self._remember(r) for r in rows]

    def _remember(self, row: PolicyPackRow) -> PublishedPack:
        published = self._verify(row)
        with self._lock:
            self._by_id[published.id] = published
        return published
