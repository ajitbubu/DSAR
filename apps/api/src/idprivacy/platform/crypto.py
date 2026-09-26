"""Envelope encryption and blind indexes behind a ``KeyProvider`` boundary.

No custom primitives: AES-256-GCM, HKDF-SHA256 and HMAC-SHA256 come from the
``cryptography`` package and the standard library. Key custody (KMS/HSM, BYOK) is
open decision D-3. ``LocalKeyProvider`` is a dev/test stand-in that derives a
per-tenant KEK from one master key.

Ciphertext format: ``v1.<key_id>.<b64 wrapped_dek>.<b64 nonce>.<b64 ciphertext>``.
The tenant id and a caller-supplied context (e.g. ``"data_principal.identifiers"``)
are bound as AEAD associated data, so ciphertext can't be moved between tenants or
columns.
"""

import base64
import hashlib
import hmac
import os
from typing import Protocol
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_VERSION = "v1"


class DecryptionError(Exception):
    pass


class KeyProvider(Protocol):
    def kek(self, tenant_id: UUID) -> tuple[str, bytes]:
        """Return ``(key_id, 32-byte KEK)`` for the tenant's current key."""

    def kek_by_id(self, tenant_id: UUID, key_id: str) -> bytes: ...

    def blind_index_key(self, tenant_id: UUID) -> bytes: ...


class LocalKeyProvider:
    """Dev/test only. Refused outside local/test by ``Settings``."""

    KEY_ID = "local-1"

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes")
        self._master = master_key

    def _derive(self, info: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(
            self._master
        )

    def kek(self, tenant_id: UUID) -> tuple[str, bytes]:
        return self.KEY_ID, self._derive(f"kek:{tenant_id}")

    def kek_by_id(self, tenant_id: UUID, key_id: str) -> bytes:
        if key_id != self.KEY_ID:
            raise DecryptionError("unknown key id")
        return self._derive(f"kek:{tenant_id}")

    def blind_index_key(self, tenant_id: UUID) -> bytes:
        return self._derive(f"bidx:{tenant_id}")


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class FieldCipher:
    def __init__(self, keys: KeyProvider) -> None:
        self._keys = keys

    @staticmethod
    def _aad(tenant_id: UUID, context: str) -> bytes:
        return f"{tenant_id}|{context}".encode()

    def encrypt(self, tenant_id: UUID, context: str, plaintext: str) -> str:
        key_id, kek = self._keys.kek(tenant_id)
        aad = self._aad(tenant_id, context)
        dek = AESGCM.generate_key(bit_length=256)
        wrap_nonce, nonce = os.urandom(12), os.urandom(12)
        wrapped = wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, dek, aad)
        ct = AESGCM(dek).encrypt(nonce, plaintext.encode(), aad)
        return ".".join((_VERSION, key_id, _b64e(wrapped), _b64e(nonce), _b64e(ct)))

    def decrypt(self, tenant_id: UUID, context: str, token: str) -> str:
        try:
            version, key_id, wrapped_b64, nonce_b64, ct_b64 = token.split(".")
            if version != _VERSION:
                raise DecryptionError("unsupported ciphertext version")
            aad = self._aad(tenant_id, context)
            kek = self._keys.kek_by_id(tenant_id, key_id)
            wrapped = _b64d(wrapped_b64)
            dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], aad)
            return AESGCM(dek).decrypt(_b64d(nonce_b64), _b64d(ct_b64), aad).decode()
        except DecryptionError:
            raise
        except Exception as exc:  # InvalidTag, ValueError, binascii errors
            raise DecryptionError("ciphertext could not be decrypted") from exc


def blind_index(keys: KeyProvider, tenant_id: UUID, kind: str, normalised_value: str) -> str:
    """Deterministic keyed hash for equality lookup of an already-normalised identifier."""
    msg = f"{kind}:{normalised_value}".encode()
    return hmac.new(keys.blind_index_key(tenant_id), msg, hashlib.sha256).hexdigest()


def build_key_provider(master_key_b64: str) -> KeyProvider:
    return LocalKeyProvider(base64.b64decode(master_key_b64))
