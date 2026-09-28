import io
import json
import logging

import pytest
import structlog

from idprivacy.platform.logging import REDACTED, configure_logging, redact

EMAIL = "priya.sharma+dsar@example.co.in"
PHONE = "+91 98765 43210"
UUID = "550e8400-e29b-41d4-a716-446655440000"


@pytest.fixture
def out() -> io.StringIO:
    stream = io.StringIO()
    structlog.reset_defaults()
    configure_logging(stream=stream)
    return stream


def _lines(out: str) -> list[dict[str, object]]:
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def test_structlog_redacts_sensitive_keys_and_values(out: io.StringIO) -> None:
    structlog.get_logger("t").info(
        f"request from {EMAIL}",
        email=EMAIL,
        phone_number=PHONE,
        access_token="eyJhbGciOi...",
        note=f"call {PHONE} or mail {EMAIL}",
        request_id=UUID,
        nested={"identifiers": [EMAIL], "count": 3},
    )
    text = out.getvalue()
    assert EMAIL not in text and "98765" not in text and "eyJhbGciOi" not in text
    (line,) = _lines(text)
    assert line["email"] == REDACTED
    assert line["access_token"] == REDACTED
    assert line["request_id"] == UUID  # identifiers stay usable for correlation
    assert line["nested"] == {"identifiers": REDACTED, "count": 3}


def test_stdlib_logging_is_redacted_too(out: io.StringIO) -> None:
    logging.getLogger("third.party").warning("login failed for %s", EMAIL)
    text = out.getvalue()
    assert EMAIL not in text
    assert REDACTED in text


def test_redact_keeps_uuid_segments_and_ints() -> None:
    assert redact({"object_id": UUID, "seq": 12345678901}) == {
        "object_id": UUID,
        "seq": 12345678901,
    }


@pytest.mark.parametrize("value", ["DPDP@1.0.0", "pack SLATEST@9.9.9 applies"])
def test_versioned_references_are_not_mistaken_for_emails(value: str) -> None:
    assert redact({"policy_pack": value}) == {"policy_pack": value}


@pytest.mark.parametrize(
    "value", ["a@b.co", "x.y+z@sub.example.co.in", "u@xn--exmple-cua.in", "priya@例え.jp"]
)
def test_email_variants_still_redacted(value: str) -> None:
    assert value not in str(redact({"note": f"contact {value} today"}))
