"""Identity resolution: normalisation edge cases and canonical sets (M2)."""

import pytest

from idprivacy.domain.identity.resolution import (
    NormalisationError,
    canonicalise,
    normalise_customer_id,
    normalise_email,
    normalise_phone,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Priya.Sharma@Example.CO.IN", "priya.sharma@example.co.in"),
        ("  priya@example.in  ", "priya@example.in"),
        ("priya@ex\u00e4mple.in", "priya@xn--exmple-cua.in"),  # IDNA -> punycode
        ("priya@EX\u00c4MPLE.in", "priya@xn--exmple-cua.in"),
        ("p.r.i.y.a@gmail.com", "p.r.i.y.a@gmail.com"),  # dots are NOT stripped
        ("priya+dsar@gmail.com", "priya+dsar@gmail.com"),  # +tags are NOT stripped
        ("Pr\u00efya@example.in", "pr\u00efya@example.in"),  # unicode local part kept
        ("Pri\u0301ya@example.in", "pr\u00edya@example.in"),  # NFC: i + accent
    ],
)
def test_email_normalisation(raw: str, expected: str) -> None:
    assert normalise_email(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not-an-email",
        "a@",
        "@example.in",
        "a@@example.in",
        "a b@example.in",
        "priya@example.in.",
    ],
)
def test_invalid_emails_rejected(raw: str) -> None:
    with pytest.raises(NormalisationError):
        normalise_email(raw)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("+919876543210", "+919876543210"),
        (" +91 98765 43210 ", "+919876543210"),
        ("+91-98765-43210", "+919876543210"),
        ("+1 (415) 555.0100", "+14155550100"),
        ("+91 98765 43210", "+919876543210"),
    ],
)
def test_phone_normalisation(raw: str, expected: str) -> None:
    assert normalise_phone(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "9876543210",
        "+0919876543210",
        "+91 98765 4321O",
        "+1234567",
        "+1234567890123456",
        "++919876543210",
        "+٩١٩٨٧٦٥٤٣٢١٠",
    ],
)
def test_invalid_phones_rejected(raw: str) -> None:
    with pytest.raises(NormalisationError):
        normalise_phone(raw)


@pytest.mark.parametrize(
    "raw, expected", [("cust-1001", "CUST-1001"), (" CUST-1001 ", "CUST-1001")]
)
def test_customer_id_normalisation(raw: str, expected: str) -> None:
    assert normalise_customer_id(raw) == expected


@pytest.mark.parametrize("raw", ["", "CUST 1001", "CUST_1001", "ＣＵＳＴ1001", "x" * 65])
def test_invalid_customer_ids_rejected(raw: str) -> None:
    with pytest.raises(NormalisationError):
        normalise_customer_id(raw)


def test_canonical_set_marks_only_the_otp_contact_as_verified() -> None:
    result = canonicalise(
        "EMAIL", "Priya@Example.in", True, [{"type": "CUSTOMER_ID", "value": "cust-1"}]
    )
    assert {(i.type, i.value, i.assurance, i.source) for i in result} == {
        ("EMAIL", "priya@example.in", "VERIFIED", "OTP"),
        ("CUSTOMER_ID", "CUST-1", "CLAIMED", "FORM"),
    }


def test_canonical_set_deduplicates_after_normalisation() -> None:
    result = canonicalise(
        "SMS",
        "+919876543210",
        True,
        [
            {"type": "CUSTOMER_ID", "value": "cust-1"},
            {"type": "CUSTOMER_ID", "value": "CUST-1"},
            {"type": "CUSTOMER_ID", "value": " Cust-1 "},
        ],
    )
    assert sorted((i.type, i.value) for i in result) == [
        ("CUSTOMER_ID", "CUST-1"),
        ("PHONE", "+919876543210"),
    ]


def test_unverified_contact_is_only_claimed() -> None:
    (ident,) = canonicalise("EMAIL", "priya@example.in", False, [])
    assert ident.assurance == "CLAIMED" and ident.source == "FORM"
