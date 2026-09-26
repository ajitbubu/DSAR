"""Test-only helpers. Mounted only when ENV=test with the mock OTP provider (M1 acceptance)."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from idprivacy.platform.auth.deps import InternalBff

router = APIRouter(prefix="/v1/test-support", tags=["test-support"], include_in_schema=False)


class MockOtp(BaseModel):
    code: str


@router.get("/otp/{challenge_id}", response_model=MockOtp, dependencies=[Depends(InternalBff())])
def latest_mock_otp(request: Request, challenge_id: UUID) -> MockOtp:
    code = request.app.state.otp_provider.peek(challenge_id)
    if code is None:
        raise HTTPException(404, "Not Found")
    return MockOtp(code=code)
