"""Public Data Principal routes (screens 1–3). Reachable only through the web BFF."""

import hmac
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from idprivacy.domain.cases.lifecycle import (
    CANCELLABLE,
    CaseStatus,
    IntakeEvent,
    InvalidTransition,
    transition,
)
from idprivacy.domain.communications.service import completion_text
from idprivacy.domain.disclosure import report as access_report
from idprivacy.domain.identity import verification
from idprivacy.domain.identity.verification import Outcome
from idprivacy.domain.intake import service as intake
from idprivacy.domain.intake.schemas import (
    Contact,
    ErasureRequestAccepted,
    ErasureRequestCreate,
    OtpConfirm,
    OtpConfirmed,
    OtpResent,
    PublicCaseStatus,
    PublicReport,
    SignInAccepted,
    SignInCreate,
)
from idprivacy.platform.auth import dp_session
from idprivacy.platform.auth.deps import DataPrincipalSession, InternalBff, client_ip
from idprivacy.platform.auth.dp_session import DataPrincipalPrincipal
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import IdentityVerification, PrivacyRequest
from idprivacy.platform.ratelimit import Limit, RateLimitExceeded

router = APIRouter(prefix="/v1/public", tags=["public"])
BffOnly = Depends(InternalBff())
ClientIp = Annotated[str, Depends(client_ip)]
DpPrincipal = Annotated[DataPrincipalPrincipal, Depends(DataPrincipalSession())]

_NOT_FOUND = HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")


def _limit(request: Request, limit: Limit, subject: str) -> None:
    try:
        request.app.state.rate_limiter.hit(limit, subject)
    except RateLimitExceeded as exc:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too Many Requests",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None


def _resolve(request: Request, sql: str, param: str) -> UUID:
    with request.app.state.app_engine.connect() as conn:
        tenant_id = conn.execute(text(sql), {"p": param}).scalar_one_or_none()
    if tenant_id is None:
        raise _NOT_FOUND
    return tenant_id  # type: ignore[no-any-return]


@router.post(
    "/requests",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ErasureRequestAccepted,
    dependencies=[BffOnly],
)
def submit_request(
    request: Request, payload: ErasureRequestCreate, ip: ClientIp
) -> ErasureRequestAccepted:
    _limit(request, request.app.state.limits.submit_per_ip, ip)
    state = request.app.state
    tenant_id = _resolve(request, "SELECT resolve_intake_tenant(:p)", payload.intake_slug)
    bidx = intake.contact_bidx(state.keys, tenant_id, payload.contact)
    _limit(request, request.app.state.limits.submit_per_contact, f"{tenant_id}:{bidx}")
    with tenant_session(state.app_engine, TenantContext(tenant_id)) as db:
        result = intake.submit(
            db,
            tenant_id=tenant_id,
            payload=payload,
            keys=state.keys,
            cipher=state.cipher,
            provider=state.otp_provider,
            settings=state.settings,
        )
    return ErasureRequestAccepted(
        display_id=result.display_id,
        challenge_id=str(result.challenge_id),
        expires_at=result.expires_at,
        destination_hint=result.destination_hint,
    )


@router.post(
    "/verifications/{challenge_id}/confirm", response_model=OtpConfirmed, dependencies=[BffOnly]
)
def confirm_otp(
    request: Request, challenge_id: UUID, body: OtpConfirm, ip: ClientIp
) -> OtpConfirmed:
    _limit(request, request.app.state.limits.confirm_per_ip, ip)
    state = request.app.state
    tenant_id = _resolve(
        request, "SELECT resolve_verification_tenant(CAST(:p AS uuid))", str(challenge_id)
    )
    with tenant_session(state.app_engine, TenantContext(tenant_id)) as db:
        result = verification.confirm(
            db, keys=state.keys, settings=state.settings, challenge_id=challenge_id, code=body.code
        )
    # The transaction has committed, so attempt counters persist even on error responses.
    if result is None:
        raise _NOT_FOUND
    if result.outcome is Outcome.VERIFIED:
        assert result.session_token and result.session_expires_at
        return OtpConfirmed(
            session_token=result.session_token, session_expires_at=result.session_expires_at
        )
    if result.outcome is Outcome.INVALID_CODE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid code")
    if result.outcome is Outcome.LOCKED:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Verification locked")
    if result.outcome is Outcome.EXPIRED:
        raise HTTPException(status.HTTP_410_GONE, "Code expired")
    raise HTTPException(status.HTTP_409_CONFLICT, "Challenge already used")


@router.post(
    "/verifications/{challenge_id}/resend",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=OtpResent,
    dependencies=[BffOnly],
)
def resend_otp(request: Request, challenge_id: UUID, ip: ClientIp) -> OtpResent:
    _limit(request, request.app.state.limits.resend_per_ip, ip)
    state = request.app.state
    tenant_id = _resolve(
        request, "SELECT resolve_verification_tenant(CAST(:p AS uuid))", str(challenge_id)
    )
    with tenant_session(state.app_engine, TenantContext(tenant_id)) as db:
        challenge = db.get(IdentityVerification, challenge_id)
        if challenge is None:
            raise _NOT_FOUND
        req = db.get(PrivacyRequest, challenge.request_id)
        assert req is not None
        channel, destination = intake.contact_for_request(state.cipher, req)
        outcome, expires_at = verification.resend(
            db,
            keys=state.keys,
            provider=state.otp_provider,
            settings=state.settings,
            challenge_id=challenge_id,
            channel=channel,
            destination=destination,
        )
    if outcome is Outcome.RESENT:
        assert expires_at is not None
        return OtpResent(expires_at=expires_at)
    if outcome is Outcome.ALREADY_USED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Challenge already used")
    raise HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "Too Many Requests",
        headers={"Retry-After": str(state.settings.otp_resend_interval_seconds)},
    )


_PUBLIC_STATUS = {
    CaseStatus.PENDING_VERIFICATION: "Verifying",
    CaseStatus.SUBMITTED: "Verifying",
    CaseStatus.VERIFICATION_FAILED: "Verification failed",
    CaseStatus.RESPONDED: "Completed",
    CaseStatus.CLOSED: "Closed",
    CaseStatus.CANCELLED: "Cancelled",
}


def _load_case(db: Session, principal: DataPrincipalPrincipal) -> PrivacyRequest:
    req = db.execute(
        select(PrivacyRequest).where(PrivacyRequest.id == principal.request_id)
    ).scalar_one_or_none()
    if req is None:
        raise _NOT_FOUND
    return req


def _report_view(db: Session, req: PrivacyRequest) -> PublicReport | None:
    r = access_report.latest_report(db, req.id)
    if r is None:
        return None
    left = max(r.max_downloads - r.download_count, 0)
    return PublicReport(
        available=r.purged_at is None and left > 0 and r.expires_at > datetime.now(UTC),
        available_until=r.expires_at,
        downloads_left=left,
        records=r.record_count,
        withheld=r.withheld_records + r.withheld_fields,
    )


def _public_view(db: Session, req: PrivacyRequest) -> PublicCaseStatus:
    status_ = CaseStatus(req.status)
    return PublicCaseStatus(
        report=_report_view(db, req),
        display_id=req.display_id,
        status=_PUBLIC_STATUS.get(status_, "In progress"),
        submitted_at=req.submitted_at,
        due_at=req.due_at,
        completion_response=completion_text(db, req.id),
        can_cancel=status_ in CANCELLABLE,
    )


@router.get("/case", response_model=PublicCaseStatus)
def get_case(request: Request, principal: DpPrincipal) -> PublicCaseStatus:
    state = request.app.state
    with tenant_session(state.app_engine, TenantContext(principal.tenant_id)) as db:
        dp_session.touch(db, principal.session_id, state.settings)
        return _public_view(db, _load_case(db, principal))


@router.post("/case/cancel", response_model=PublicCaseStatus)
def cancel_case(request: Request, principal: DpPrincipal) -> PublicCaseStatus:
    state = request.app.state
    with tenant_session(state.app_engine, TenantContext(principal.tenant_id)) as db:
        req = _load_case(db, principal)
        try:
            transition(
                db,
                req,
                IntakeEvent.CANCEL,
                actor_type="DATA_PRINCIPAL",
                actor_ref=f"data_principal:{req.id}",
            )
        except InvalidTransition:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "Request can no longer be cancelled"
            ) from None
        req.closed_at = datetime.now(UTC)
        return _public_view(db, req)


# ---------- Access reports and returning sign-in (access milestone A3) -----------------

_NOT_YET_VERIFIED = {
    CaseStatus.SUBMITTED,
    CaseStatus.PENDING_VERIFICATION,
    CaseStatus.VERIFICATION_FAILED,
}


@router.post(
    "/sessions",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=SignInAccepted,
    dependencies=[BffOnly],
)
def request_sign_in(request: Request, payload: SignInCreate, ip: ClientIp) -> SignInAccepted:
    """Always the same answer, whether or not the reference and contact match a request:
    a code is sent only when they do, so this can't be used to discover requests."""
    state = request.app.state
    _limit(request, state.limits.sign_in_per_ip, ip)
    tenant_id = _resolve(request, "SELECT resolve_intake_tenant(:p)", payload.intake_slug)
    bidx = intake.contact_bidx(state.keys, tenant_id, payload.contact)
    _limit(request, state.limits.sign_in_per_contact, f"{tenant_id}:{bidx}")
    challenge_id = uuid4()
    expires_at = datetime.now(UTC) + timedelta(seconds=state.settings.otp_ttl_seconds)
    with tenant_session(state.app_engine, TenantContext(tenant_id)) as db:
        req = db.execute(
            select(PrivacyRequest).where(PrivacyRequest.display_id == payload.reference)
        ).scalar_one_or_none()
        if req is not None and CaseStatus(req.status) not in _NOT_YET_VERIFIED:
            channel, destination = intake.contact_for_request(state.cipher, req)
            stored = intake.contact_bidx(
                state.keys, tenant_id, Contact(channel=channel, value=destination)
            )
            if hmac.compare_digest(stored, bidx):
                challenge = verification.issue(
                    db,
                    keys=state.keys,
                    provider=state.otp_provider,
                    settings=state.settings,
                    request=req,
                    channel=channel,
                    destination=destination,
                    purpose="SIGN_IN",
                )
                challenge_id, expires_at = challenge.id, challenge.expires_at
    return SignInAccepted(
        challenge_id=str(challenge_id),
        expires_at=expires_at,
        destination_hint=intake.destination_hint(payload.contact),
    )


@router.get("/case/report/{fmt}")
def download_report(
    request: Request, principal: DpPrincipal, fmt: Literal["json", "html"]
) -> Response:
    state = request.app.state
    with tenant_session(state.app_engine, TenantContext(principal.tenant_id)) as db:
        dp_session.touch(db, principal.session_id, state.settings)
        try:
            d = access_report.download(
                db,
                request_id=principal.request_id,
                fmt=fmt,
                cipher=state.cipher,
                store=state.services.blob_store,
            )
        except LookupError:
            raise _NOT_FOUND from None
        except access_report.ReportGone:
            raise HTTPException(
                status.HTTP_410_GONE, "This report is no longer available"
            ) from None
    headers = {
        "Content-Disposition": f'attachment; filename="{d.filename}"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if fmt == "html":
        headers["Content-Security-Policy"] = (
            "sandbox; default-src 'none'; style-src 'unsafe-inline'"
        )
    return Response(d.body, media_type=d.media_type, headers=headers)
