"""OTP identity verification (threat model T-01, T-02, T-03).

- 6-digit codes from ``secrets``, stored only as a keyed HMAC (the key never touches the
  DB), so a database dump can't be brute-forced offline.
- The challenge row is locked FOR UPDATE, so concurrent guesses are counted exactly.
- A challenge is single-use. Resending replaces the code but never resets attempts.
"""

import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from idprivacy.config import Settings
from idprivacy.domain.audit import service as audit
from idprivacy.domain.cases.lifecycle import IntakeEvent, transition
from idprivacy.domain.identity.otp import OtpProvider
from idprivacy.platform import outbox
from idprivacy.platform.auth import dp_session
from idprivacy.platform.crypto import KeyProvider, blind_index
from idprivacy.platform.models import IdentityVerification, PrivacyRequest


class ChallengeStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class Outcome(StrEnum):
    VERIFIED = "VERIFIED"
    INVALID_CODE = "INVALID_CODE"
    LOCKED = "LOCKED"
    EXPIRED = "EXPIRED"
    ALREADY_USED = "ALREADY_USED"
    RESEND_TOO_SOON = "RESEND_TOO_SOON"
    RESEND_LIMIT = "RESEND_LIMIT"
    RESENT = "RESENT"


@dataclass(frozen=True)
class ConfirmResult:
    outcome: Outcome
    session_token: str | None = None
    session_expires_at: datetime | None = None
    attempts_remaining: int | None = None


def _generate_code() -> str:
    return f"{secrets.randbelow(10**6):06d}"


def _hash(keys: KeyProvider, tenant_id: UUID, challenge_id: UUID, code: str) -> str:
    return blind_index(keys, tenant_id, "otp", f"{challenge_id}:{code}")


def _actor(request_id: UUID) -> str:
    return f"data_principal:{request_id}"


def issue(
    session: Session,
    *,
    keys: KeyProvider,
    provider: OtpProvider,
    settings: Settings,
    request: PrivacyRequest,
    channel: str,
    destination: str,
    purpose: str = "INTAKE",
) -> IdentityVerification:
    now = datetime.now(UTC)
    challenge = IdentityVerification(
        tenant_id=request.tenant_id,
        request_id=request.id,
        method="OTP_EMAIL" if channel == "EMAIL" else "OTP_SMS",
        purpose=purpose,
        provider=provider.name,
        challenge_hash="pending",
        status=ChallengeStatus.PENDING,
        attempts=0,
        max_attempts=settings.otp_max_attempts,
        resend_count=0,
        last_sent_at=now,
        expires_at=now + timedelta(seconds=settings.otp_ttl_seconds),
    )
    session.add(challenge)
    session.flush()
    code = _generate_code()
    challenge.challenge_hash = _hash(keys, request.tenant_id, challenge.id, code)
    provider.send(challenge_id=challenge.id, channel=channel, destination=destination, code=code)
    audit.append(
        session,
        tenant_id=request.tenant_id,
        actor_type="SYSTEM",
        actor_ref="system:intake",
        action="identity.challenge_issued",
        object_type="identity_verification",
        object_id=challenge.id,
        details={"method": challenge.method, "provider": provider.name, "purpose": purpose},
    )
    return challenge


def _lock(session: Session, challenge_id: UUID) -> IdentityVerification | None:
    return session.execute(
        select(IdentityVerification)
        .where(IdentityVerification.id == challenge_id)
        .with_for_update()
    ).scalar_one_or_none()


def _request(session: Session, challenge: IdentityVerification) -> PrivacyRequest:
    return session.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == challenge.request_id).with_for_update()
    ).scalar_one()


def confirm(
    session: Session, *, keys: KeyProvider, settings: Settings, challenge_id: UUID, code: str
) -> ConfirmResult | None:
    challenge = _lock(session, challenge_id)
    if challenge is None:
        return None
    actor = _actor(challenge.request_id)
    if challenge.status == ChallengeStatus.VERIFIED:
        audit.append(
            session,
            tenant_id=challenge.tenant_id,
            actor_type="DATA_PRINCIPAL",
            actor_ref=actor,
            action="identity.challenge_replayed",
            object_type="identity_verification",
            object_id=challenge.id,
        )
        return ConfirmResult(Outcome.ALREADY_USED)
    if challenge.status == ChallengeStatus.FAILED:
        return ConfirmResult(Outcome.LOCKED)
    if challenge.status == ChallengeStatus.EXPIRED or datetime.now(UTC) >= challenge.expires_at:
        challenge.status = ChallengeStatus.EXPIRED
        return ConfirmResult(Outcome.EXPIRED)

    expected = challenge.challenge_hash
    supplied = _hash(keys, challenge.tenant_id, challenge.id, code)
    request = _request(session, challenge)
    sign_in = challenge.purpose == "SIGN_IN"
    if hmac.compare_digest(expected, supplied) and sign_in:
        # A returning requester: reopen a tracking session, never touch the case state.
        challenge.status = ChallengeStatus.VERIFIED
        challenge.verified_at = datetime.now(UTC)
        token, expires = dp_session.create(
            session, tenant_id=challenge.tenant_id, request_id=request.id, settings=settings
        )
        audit.append(
            session,
            tenant_id=challenge.tenant_id,
            actor_type="DATA_PRINCIPAL",
            actor_ref=actor,
            action="identity.signed_in",
            object_type="identity_verification",
            object_id=challenge.id,
            details={"attempts": challenge.attempts + 1},
        )
        return ConfirmResult(Outcome.VERIFIED, session_token=token, session_expires_at=expires)
    if hmac.compare_digest(expected, supplied):
        challenge.status = ChallengeStatus.VERIFIED
        challenge.verified_at = datetime.now(UTC)
        transition(
            session, request, IntakeEvent.VERIFY, actor_type="DATA_PRINCIPAL", actor_ref=actor
        )
        # Hand the case to the post-verification pipeline (worker), atomically.
        outbox.enqueue(
            session,
            tenant_id=challenge.tenant_id,
            topic="case.verified",
            payload={"request_id": request.id},
        )
        token, expires = dp_session.create(
            session, tenant_id=challenge.tenant_id, request_id=request.id, settings=settings
        )
        audit.append(
            session,
            tenant_id=challenge.tenant_id,
            actor_type="DATA_PRINCIPAL",
            actor_ref=actor,
            action="identity.verified",
            object_type="identity_verification",
            object_id=challenge.id,
            details={"attempts": challenge.attempts + 1},
        )
        return ConfirmResult(Outcome.VERIFIED, session_token=token, session_expires_at=expires)

    challenge.attempts += 1
    remaining = challenge.max_attempts - challenge.attempts
    audit.append(
        session,
        tenant_id=challenge.tenant_id,
        actor_type="DATA_PRINCIPAL",
        actor_ref=actor,
        action="identity.attempt_failed",
        object_type="identity_verification",
        object_id=challenge.id,
        details={"attempts": challenge.attempts},
    )
    if remaining <= 0 and sign_in:
        challenge.status = ChallengeStatus.FAILED  # the case itself is unaffected
    elif remaining <= 0:
        challenge.status = ChallengeStatus.FAILED
        transition(
            session,
            request,
            IntakeEvent.FAIL_VERIFICATION,
            actor_type="SYSTEM",
            actor_ref="system:identity",
        )
    return ConfirmResult(Outcome.INVALID_CODE, attempts_remaining=max(remaining, 0))


def resend(
    session: Session,
    *,
    keys: KeyProvider,
    provider: OtpProvider,
    settings: Settings,
    challenge_id: UUID,
    channel: str,
    destination: str,
) -> tuple[Outcome, datetime | None]:
    challenge = _lock(session, challenge_id)
    if challenge is None:
        raise LookupError(challenge_id)
    if challenge.status == ChallengeStatus.VERIFIED:
        return Outcome.ALREADY_USED, None
    if challenge.status == ChallengeStatus.FAILED:
        return Outcome.LOCKED, None
    now = datetime.now(UTC)
    if challenge.resend_count >= settings.otp_max_resends:
        return Outcome.RESEND_LIMIT, None
    if now < challenge.last_sent_at + timedelta(seconds=settings.otp_resend_interval_seconds):
        return Outcome.RESEND_TOO_SOON, None
    code = _generate_code()
    challenge.challenge_hash = _hash(keys, challenge.tenant_id, challenge.id, code)
    challenge.status = ChallengeStatus.PENDING
    challenge.resend_count += 1
    challenge.last_sent_at = now
    challenge.expires_at = now + timedelta(seconds=settings.otp_ttl_seconds)
    provider.send(challenge_id=challenge.id, channel=channel, destination=destination, code=code)
    audit.append(
        session,
        tenant_id=challenge.tenant_id,
        actor_type="DATA_PRINCIPAL",
        actor_ref=_actor(challenge.request_id),
        action="identity.challenge_resent",
        object_type="identity_verification",
        object_id=challenge.id,
        details={"resend_count": challenge.resend_count},
    )
    return Outcome.RESENT, challenge.expires_at
