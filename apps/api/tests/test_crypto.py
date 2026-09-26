import uuid

import pytest

from idprivacy.platform.crypto import (
    DecryptionError,
    FieldCipher,
    LocalKeyProvider,
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
