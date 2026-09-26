"""OIDC access-token validation. The API is a resource server (ADR-0003).

Uses PyJWT. The algorithm allowlist is checked against the token header *before* key
resolution, and passed again to ``jwt.decode``, which blocks ``alg=none`` and HS/RS
confusion.
"""

from collections.abc import Callable
from typing import Any

import jwt

KeyResolver = Callable[[str], Any]


class InvalidTokenError(Exception):
    """Raised for any token problem. The reason is deliberately not surfaced to clients."""


class OidcVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        algorithms: list[str],
        key_resolver: KeyResolver,
        leeway_seconds: int = 30,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._algorithms = list(algorithms)
        self._resolve_key = key_resolver
        self._leeway = leeway_seconds

    def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in self._algorithms:
                raise InvalidTokenError("algorithm not allowed")
            key = self._resolve_key(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except InvalidTokenError:
            raise
        except Exception as exc:  # any PyJWT / JWKS failure
            raise InvalidTokenError("token rejected") from exc
        return claims


def jwks_key_resolver(jwks_url: str) -> KeyResolver:
    client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300, timeout=5)

    def resolve(token: str) -> Any:
        return client.get_signing_key_from_jwt(token).key

    return resolve
