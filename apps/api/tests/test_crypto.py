import base64
import hashlib
import hmac
import json
import os
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from idprivacy.platform.crypto import (
    DecryptionError,
    FieldCipher,
    KeyServiceError,
    LocalKeyProvider,
    VaultTransitKeyProvider,
    blind_index,
)

KEYS = LocalKeyProvider(b"k" * 32)
CIPHER = FieldCipher(KEYS)
T1, T2 = uuid.uuid4(), uuid.uuid4()
CTX = "data_principal.identifiers"


def test_round_trip_and_ciphertext_hides_plaintext() -> None:
    token = CIPHER.encrypt(T1, CTX, "priya@example.in")
    assert "priya" not in token
    assert CIPHER.decrypt(T1, CTX, token) == "priya@example.in"


def test_each_encryption_uses_fresh_randomness() -> None:
    assert CIPHER.encrypt(T1, CTX, "x") != CIPHER.encrypt(T1, CTX, "x")


def test_ciphertext_bound_to_tenant() -> None:
    token = CIPHER.encrypt(T1, CTX, "secret")
    with pytest.raises(DecryptionError):
        CIPHER.decrypt(T2, CTX, token)


def test_ciphertext_bound_to_context() -> None:
    token = CIPHER.encrypt(T1, CTX, "secret")
    with pytest.raises(DecryptionError):
        CIPHER.decrypt(T1, "app_user.email", token)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t[:-2] + ("A" if t[-2] != "A" else "B") + t[-1],
        lambda t: "v2" + t[2:],
        lambda t: t.replace("local-1", "local-9"),
        lambda t: "garbage",
    ],
)
def test_tampered_ciphertext_rejected(mutate) -> None:
    token = CIPHER.encrypt(T1, CTX, "secret")
    with pytest.raises(DecryptionError):
        CIPHER.decrypt(T1, CTX, mutate(token))


def test_blind_index_deterministic_per_tenant_and_distinct_across_tenants() -> None:
    a = blind_index(KEYS, T1, "email", "priya@example.in")
    assert a == blind_index(KEYS, T1, "email", "priya@example.in")
    assert a != blind_index(KEYS, T2, "email", "priya@example.in")
    assert a != blind_index(KEYS, T1, "phone", "priya@example.in")


def test_master_key_length_enforced() -> None:
    with pytest.raises(ValueError):
        LocalKeyProvider(b"short")


def test_local_ciphertext_format_unchanged() -> None:
    """Rows written before the KeyProvider refactor must still decrypt."""
    tenant = uuid.UUID("00000000-0000-0000-0000-000000000001")
    legacy = (
        "v1.local-1.chIeCCM1gnJGUw7QGpdFAzkIpX-4PUU28Dwek8sZd-DvIfFBWbWG44gw34HTNPWhGs3ftpzRCp2nKV3p"
        ".pSIDWyjyaNrgVTcO.wF8QPT95PSoHJCzU85ioKdowsb6bjA"
    )
    assert CIPHER.decrypt(tenant, CTX, legacy) == "legacy"


class FakeTransit:
    """Just enough of Vault's Transit API: keys, encrypt, decrypt, hmac."""

    def __init__(self) -> None:
        self.keys: dict[str, bytes] = {}
        self.down = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("vault down")
        if request.headers.get("X-Vault-Token") != "tok":
            return httpx.Response(403, json={"errors": ["permission denied"]})
        _, _, mount, op, name, *rest = request.url.path.split("/")
        assert mount == "transit"
        body = json.loads(request.content)
        if op == "keys":
            self.keys.setdefault(name, os.urandom(32))
            return httpx.Response(204)
        key = self.keys.get(name)
        if key is None:
            return httpx.Response(400, json={"errors": ["encryption key not found"]})
        if op == "encrypt":
            nonce = os.urandom(12)
            ct = nonce + AESGCM(key).encrypt(nonce, base64.b64decode(body["plaintext"]), None)
            ciphertext = "vault:v1:" + base64.b64encode(ct).decode()
            return httpx.Response(200, json={"data": {"ciphertext": ciphertext}})
        if op == "decrypt":
            raw = base64.b64decode(body["ciphertext"].removeprefix("vault:v1:"))
            try:
                pt = AESGCM(key).decrypt(raw[:12], raw[12:], None)
            except Exception:
                return httpx.Response(400, json={"errors": ["message authentication failed"]})
            return httpx.Response(200, json={"data": {"plaintext": base64.b64encode(pt).decode()}})
        if op == "hmac":
            assert rest == ["sha2-256"] and body["key_version"] == 1
            mac = hmac.new(key, base64.b64decode(body["input"]), hashlib.sha256).digest()
            digest = "vault:v1:" + base64.b64encode(mac).decode()
            return httpx.Response(200, json={"data": {"hmac": digest}})
        return httpx.Response(404)


@pytest.fixture
def vault() -> tuple[FakeTransit, VaultTransitKeyProvider]:
    fake = FakeTransit()
    client = httpx.Client(base_url="http://vault", transport=httpx.MockTransport(fake))
    keys = VaultTransitKeyProvider("http://vault", "tok", client=client)
    keys.provision(T1)
    keys.provision(T2)
    return fake, keys


def test_vault_round_trip_and_bindings(vault) -> None:  # type: ignore[no-untyped-def]
    _, keys = vault
    cipher = FieldCipher(keys)
    token = cipher.encrypt(T1, CTX, "priya@example.in")
    assert token.split(".")[1] == "vault" and "priya" not in token
    assert cipher.decrypt(T1, CTX, token) == "priya@example.in"
    with pytest.raises(DecryptionError):
        cipher.decrypt(T2, CTX, token)  # other tenant's KEK can't unwrap the DEK
    with pytest.raises(DecryptionError):
        cipher.decrypt(T1, "app_user.email", token)


def test_vault_blind_index_is_deterministic_hex_per_tenant(vault) -> None:  # type: ignore[no-untyped-def]
    _, keys = vault
    a = blind_index(keys, T1, "email", "priya@example.in")
    assert len(a) == 64 and int(a, 16) >= 0
    assert a == blind_index(keys, T1, "email", "priya@example.in")
    assert a != blind_index(keys, T2, "email", "priya@example.in")


def test_vault_outage_is_not_reported_as_bad_ciphertext(vault) -> None:  # type: ignore[no-untyped-def]
    fake, keys = vault
    cipher = FieldCipher(keys)
    token = cipher.encrypt(T1, CTX, "secret")
    fake.down = True
    with pytest.raises(KeyServiceError):
        cipher.decrypt(T1, CTX, token)
    with pytest.raises(KeyServiceError):
        blind_index(keys, T1, "email", "x")


def test_local_ciphertext_not_accepted_by_vault_provider(vault) -> None:  # type: ignore[no-untyped-def]
    _, keys = vault
    with pytest.raises(DecryptionError):
        FieldCipher(keys).decrypt(T1, CTX, CIPHER.encrypt(T1, CTX, "secret"))
