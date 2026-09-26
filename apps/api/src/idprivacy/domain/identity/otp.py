"""OTP provider boundary. The only v1 implementation is a mock.

``build_otp_provider`` refuses the mock outside local/test. ``Settings`` enforces the
same rule; this is a second guard at the point of use.
"""

from collections import OrderedDict
from threading import Lock
from typing import Protocol
from uuid import UUID

from idprivacy.config import DEV_ENVIRONMENTS, Settings


class OtpProvider(Protocol):
    name: str

    def send(self, *, challenge_id: UUID, channel: str, destination: str, code: str) -> None: ...


class MockOtpProvider:
    """Keeps the latest code per challenge in memory so tests (ENV=test) can read it.

    The destination isn't retained. The store is bounded so it can't grow without limit.
    """

    name = "mock"
    _MAX_ENTRIES = 1000

    def __init__(self) -> None:
        self._codes: OrderedDict[UUID, str] = OrderedDict()
        self._lock = Lock()

    def send(self, *, challenge_id: UUID, channel: str, destination: str, code: str) -> None:
        with self._lock:
            self._codes[challenge_id] = code
            self._codes.move_to_end(challenge_id)
            while len(self._codes) > self._MAX_ENTRIES:
                self._codes.popitem(last=False)

    def peek(self, challenge_id: UUID) -> str | None:
        with self._lock:
            return self._codes.get(challenge_id)


def build_otp_provider(settings: Settings) -> OtpProvider:
    if settings.otp_provider == "mock":
        if settings.env not in DEV_ENVIRONMENTS:
            raise RuntimeError("mock OTP provider is only permitted in local/test")
        return MockOtpProvider()
    raise RuntimeError(f"unsupported OTP provider {settings.otp_provider!r}")
