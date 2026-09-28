"""Fixed-window rate limiting for public endpoints (threat model T-02, T-17).

Keys never contain personal data: subjects (client IP, contact blind index) are hashed.
"""

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import redis

if TYPE_CHECKING:
    from idprivacy.config import Settings


@dataclass(frozen=True)
class Limit:
    scope: str
    max_hits: int
    window_seconds: int


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        super().__init__("rate limit exceeded")
        self.retry_after = retry_after


class RateLimiter(Protocol):
    def hit(self, limit: Limit, subject: str) -> None:
        """Record one hit. Raises ``RateLimitExceeded`` when over the limit."""


def _key(limit: Limit, subject: str) -> str:
    digest = hashlib.sha256(subject.encode()).hexdigest()[:32]
    return f"rl:{limit.scope}:{digest}"


class RedisRateLimiter:
    def __init__(self, client: redis.Redis) -> None:
        self._redis = client

    def hit(self, limit: Limit, subject: str) -> None:
        key = _key(limit, subject)
        pipe = self._redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, limit.window_seconds, nx=True)
        pipe.ttl(key)
        count, _, ttl = pipe.execute()
        if int(count) > limit.max_hits:
            raise RateLimitExceeded(max(int(ttl), 1))

    def reset(self) -> None:
        """Test support only (mounted when ENV=test)."""
        for key in self._redis.scan_iter("rl:*"):
            self._redis.delete(key)


class MemoryRateLimiter:
    """Single-process limiter for local/test only (refused elsewhere by Settings)."""

    def __init__(self) -> None:
        self._hits: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def hit(self, limit: Limit, subject: str) -> None:
        key, now = _key(limit, subject), time.monotonic()
        with self._lock:
            count, reset_at = self._hits.get(key, (0, now + limit.window_seconds))
            if now >= reset_at:
                count, reset_at = 0, now + limit.window_seconds
            count += 1
            self._hits[key] = (count, reset_at)
        if count > limit.max_hits:
            raise RateLimitExceeded(max(int(reset_at - now), 1))

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


@dataclass(frozen=True)
class PublicLimits:
    submit_per_ip: Limit
    submit_per_contact: Limit  # stops OTP-bombing one person
    confirm_per_ip: Limit
    resend_per_ip: Limit


def _parse(scope: str, spec: str) -> Limit:
    hits, _, window = spec.partition("/")
    return Limit(scope, int(hits), int(window))


def public_limits(settings: "Settings") -> PublicLimits:
    return PublicLimits(
        submit_per_ip=_parse("submit:ip", settings.rate_limit_submit_per_ip),
        submit_per_contact=_parse("submit:contact", settings.rate_limit_submit_per_contact),
        confirm_per_ip=_parse("confirm:ip", settings.rate_limit_confirm_per_ip),
        resend_per_ip=_parse("resend:ip", settings.rate_limit_resend_per_ip),
    )
