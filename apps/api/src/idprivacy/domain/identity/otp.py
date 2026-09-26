"""OTP provider boundary. The only v1 implementation is a mock (M1 fills it in).

``build_otp_provider`` refuses the mock outside local/test. ``Settings`` enforces the
same rule; this is a second guard at the point of use.
"""

from typing import Protocol

from idprivacy.config import DEV_ENVIRONMENTS, Settings


class OtpProvider(Protocol):
    name: str

    def send(self, *, channel: str, destination: str, code: str) -> None: ...


class MockOtpProvider:
    name = "mock"

    def __init__(self) -> None:
        self.outbox: list[tuple[str, str, str]] = []

    def send(self, *, channel: str, destination: str, code: str) -> None:
        self.outbox.append((channel, destination, code))


def build_otp_provider(settings: Settings) -> OtpProvider:
    if settings.otp_provider == "mock":
        if settings.env not in DEV_ENVIRONMENTS:
            raise RuntimeError("mock OTP provider is only permitted in local/test")
        return MockOtpProvider()
    raise RuntimeError(f"unsupported OTP provider {settings.otp_provider!r}")
