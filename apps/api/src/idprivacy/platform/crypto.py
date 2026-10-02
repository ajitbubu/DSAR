"""Envelope encryption and blind indexes behind a ``KeyProvider`` boundary.

No custom primitives: AES-256-GCM, HKDF-SHA256 and HMAC-SHA256 come from the
``cryptography`` package and the standard library. Key custody is decision D-3: in
production a ``VaultTransitKeyProvider`` wraps data keys and computes blind indexes
inside HashiCorp Vault's Transit engine, so tenant key material never leaves Vault.
``LocalKeyProvider`` is a dev/test stand-in that derives a per-tenant KEK from one
master key.

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

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_VERSION = "v1"


class DecryptionError(Exception):
    pass


class KeyServiceError(Exception):
    """The key service could not be reached or refused the call. Not a bad ciphertext."""


class KeyProvider(Protocol):
    def wrap_dek(self, tenant_id: UUID, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        """Wrap a data key under the tenant's current KEK. Returns ``(key_id, wrapped)``."""

    def unwrap_dek(self, tenant_id: UUID, key_id: str, wrapped: bytes, aad: bytes) -> bytes: ...

    def mac(self, tenant_id: UUID, msg: bytes) -> str:
        """Hex HMAC-SHA256 of ``msg`` under the tenant's blind-index key."""


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

    def wrap_dek(self, tenant_id: UUID, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        wrap_nonce = os.urandom(12)
        kek = self._derive(f"kek:{tenant_id}")
        return self.KEY_ID, wrap_nonce + AESGCM(kek).encrypt(wrap_nonce, dek, aad)

    def unwrap_dek(self, tenant_id: UUID, key_id: str, wrapped: bytes, aad: bytes) -> bytes:
        if key_id != self.KEY_ID:
            raise DecryptionError("unknown key id")
        kek = self._derive(f"kek:{tenant_id}")
        return AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], aad)

    def mac(self, tenant_id: UUID, msg: bytes) -> str:
        return hmac.new(self._derive(f"bidx:{tenant_id}"), msg, hashlib.sha256).hexdigest()


class VaultTransitKeyProvider:
    """Production key custody (D-3): HashiCorp Vault Transit, one pair of keys per tenant.

    ``idp-kek-<tenant>`` wraps data keys and ``idp-bidx-<tenant>`` computes blind indexes.
    Neither is exportable. The KEK can be rotated in Vault at any time: the key version is
    inside the wrapped DEK. The blind-index key must never be rotated, because every
    stored ``bidx`` would stop matching; HMACs are pinned to key version 1.
    """

    KEY_ID = "vault"

    def __init__(
        self,
        addr: str,
        token: str,
        mount: str = "transit",
        *,
        client: httpx.Client | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._mount = mount.strip("/")
        self._http = client or httpx.Client(base_url=addr, timeout=timeout)
        self._headers = {"X-Vault-Token": token}

    @staticmethod
    def kek_name(tenant_id: UUID) -> str:
        return f"idp-kek-{tenant_id}"

    @staticmethod
    def bidx_name(tenant_id: UUID) -> str:
        return f"idp-bidx-{tenant_id}"

    def _post(self, path: str, body: dict[str, object]) -> httpx.Response:
        try:
            return self._http.post(f"/v1/{self._mount}/{path}", json=body, headers=self._headers)
        except httpx.HTTPError as exc:
            raise KeyServiceError(f"vault transit unreachable: {type(exc).__name__}") from exc

    def _data(self, resp: httpx.Response) -> dict[str, str]:
        if resp.status_code != 200:
            raise KeyServiceError(f"vault transit returned {resp.status_code}")
        data: dict[str, str] = resp.json()["data"]
        return data

    def provision(self, tenant_id: UUID) -> None:
        """Create the tenant's keys. Safe to repeat: Vault leaves an existing key unchanged."""
        for name in (self.kek_name(tenant_id), self.bidx_name(tenant_id)):
            resp = self._post(f"keys/{name}", {"type": "aes256-gcm96", "exportable": False})
            if resp.status_code not in (200, 204):
                raise KeyServiceError(f"vault transit returned {resp.status_code}")

    def wrap_dek(self, tenant_id: UUID, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        # The DEK layer already binds ``aad``; the KEK is per tenant, so a wrapped DEK
        # can't be unwrapped for another tenant either.
        resp = self._post(
            f"encrypt/{self.kek_name(tenant_id)}", {"plaintext": base64.b64encode(dek).decode()}
        )
        return self.KEY_ID, self._data(resp)["ciphertext"].encode()

    def unwrap_dek(self, tenant_id: UUID, key_id: str, wrapped: bytes, aad: bytes) -> bytes:
        if key_id != self.KEY_ID:
            raise DecryptionError("unknown key id")
        resp = self._post(f"decrypt/{self.kek_name(tenant_id)}", {"ciphertext": wrapped.decode()})
        if resp.status_code == 400:  # Vault's answer to a ciphertext it can't open
            raise DecryptionError("wrapped key could not be unwrapped")
        return base64.b64decode(self._data(resp)["plaintext"])

    def mac(self, tenant_id: UUID, msg: bytes) -> str:
        resp = self._post(
            f"hmac/{self.bidx_name(tenant_id)}/sha2-256",
            {"input": base64.b64encode(msg).decode(), "key_version": 1},
        )
        _, _, digest = self._data(resp)["hmac"].rpartition(":")  # "vault:v1:<b64>"
        return base64.b64decode(digest).hex()


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
        aad = self._aad(tenant_id, context)
        dek = AESGCM.generate_key(bit_length=256)
        key_id, wrapped = self._keys.wrap_dek(tenant_id, dek, aad)
        nonce = os.urandom(12)
        ct = AESGCM(dek).encrypt(nonce, plaintext.encode(), aad)
        return ".".join((_VERSION, key_id, _b64e(wrapped), _b64e(nonce), _b64e(ct)))

    def decrypt(self, tenant_id: UUID, context: str, token: str) -> str:
        try:
            version, key_id, wrapped_b64, nonce_b64, ct_b64 = token.split(".")
            if version != _VERSION:
                raise DecryptionError("unsupported ciphertext version")
            aad = self._aad(tenant_id, context)
            dek = self._keys.unwrap_dek(tenant_id, key_id, _b64d(wrapped_b64), aad)
            return AESGCM(dek).decrypt(_b64d(nonce_b64), _b64d(ct_b64), aad).decode()
        except (DecryptionError, KeyServiceError):
            raise
        except Exception as exc:  # InvalidTag, ValueError, binascii errors
            raise DecryptionError("ciphertext could not be decrypted") from exc


def blind_index(keys: KeyProvider, tenant_id: UUID, kind: str, normalised_value: str) -> str:
    """Deterministic keyed hash for equality lookup of an already-normalised identifier."""
    return keys.mac(tenant_id, f"{kind}:{normalised_value}".encode())


def build_key_provider(master_key_b64: str) -> KeyProvider:
    return LocalKeyProvider(base64.b64decode(master_key_b64))
