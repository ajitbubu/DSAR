"""Conformance kit: behaviour every connector must prove before it's enabled (ADR-0006).

Usage in a connector's test suite::

    kit = ConformanceKit(target)
    failures = kit.run_all()
    assert failures == {}

The target describes identifiers that match known records, disposable records the kit
may destroy, and (optionally) a raw HTTP hook for malformed-input and auth checks.
"""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from idprivacy_connector_sdk.connector import Connector, idempotency_key
from idprivacy_connector_sdk.models import (
    Action,
    ActionRequest,
    DiscoveryRequest,
    EvidenceRequest,
    Identifier,
    IdentifierType,
    VerifyRequest,
)

RawPost = Callable[[str, Any, bool], int]  # (path, json body, authenticated) -> status code


@dataclass
class ConformanceTarget:
    connector: Connector
    matching: list[Identifier]  # must match at least 3 records
    non_matching: list[Identifier]  # must match nothing
    disposable_refs: list[str]  # at least 3 records the kit may delete
    raw_post: RawPost | None = None
    namespace: str = field(default="conformance")


class ConformanceKit:
    def __init__(self, target: ConformanceTarget) -> None:
        self.t = target
        self.c = target.connector

    def _key(self, *parts: object) -> str:
        return idempotency_key(self.t.namespace, *parts)

    # -- discovery ---------------------------------------------------------------------

    def check_connection(self) -> None:
        status = self.c.test_connection()
        assert status.ok, "test_connection reported not ok"
        assert status.descriptor.supported_actions, "descriptor lists no actions"

    def check_pagination_is_complete_and_stable(self) -> None:
        single = self.c.discover(DiscoveryRequest(identifiers=self.t.matching, page_size=100))
        assert single.next_page_token is None, "expected all matches in one large page"
        assert len(single.matches) >= 3, "target must match at least 3 records"
        refs: list[str] = []
        token: str | None = None
        for _ in range(1000):
            page = self.c.discover(
                DiscoveryRequest(identifiers=self.t.matching, page_size=1, page_token=token)
            )
            assert len(page.matches) <= 1, "page_size not honoured"
            refs += [m.source_record_ref for m in page.matches]
            token = page.next_page_token
            if token is None:
                break
        assert len(refs) == len(set(refs)), "pagination returned duplicates"
        assert set(refs) == {m.source_record_ref for m in single.matches}, (
            "paged and unpaged results differ"
        )

    def check_non_matching_identifiers_find_nothing(self) -> None:
        page = self.c.discover(DiscoveryRequest(identifiers=self.t.non_matching))
        assert page.matches == [], "non-matching identifiers returned records"

    def check_fingerprints_are_stable(self) -> None:
        a = self.c.discover(DiscoveryRequest(identifiers=self.t.matching, page_size=100))
        b = self.c.discover(DiscoveryRequest(identifiers=self.t.matching, page_size=100))
        fa = {m.source_record_ref: m.content_fingerprint for m in a.matches}
        fb = {m.source_record_ref: m.content_fingerprint for m in b.matches}
        assert fa == fb, "content fingerprints changed without the record changing"

    # -- idempotent actions --------------------------------------------------------------

    def check_duplicate_key_replay(self) -> None:
        ref = self.t.disposable_refs[0]
        req = ActionRequest(
            idempotency_key=self._key("replay", ref), action=Action.DELETE, source_record_ref=ref
        )
        first = self.c.execute_action(req)
        second = self.c.execute_action(req)
        assert first.replayed is False, "first call must not be a replay"
        assert second.replayed is True, "second call with the same key must be a replay"
        assert first.receipt_id == second.receipt_id, "replay returned a different receipt"
        assert self.c.verify_action(VerifyRequest(source_record_ref=ref)).observed == "ABSENT"

    def check_concurrent_same_key_applies_once(self) -> None:
        ref = self.t.disposable_refs[1]
        req = ActionRequest(
            idempotency_key=self._key("concurrent", ref),
            action=Action.DELETE,
            source_record_ref=ref,
        )
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.c.execute_action(req), range(8)))
        assert len({r.receipt_id for r in results}) == 1, "concurrent calls made >1 receipt"
        assert sum(not r.replayed for r in results) == 1, "effect applied more than once"

    def check_new_key_on_absent_record(self) -> None:
        ref = self.t.disposable_refs[2]
        first = self.c.execute_action(
            ActionRequest(
                idempotency_key=self._key("absent-1", ref),
                action=Action.DELETE,
                source_record_ref=ref,
            )
        )
        again = self.c.execute_action(
            ActionRequest(
                idempotency_key=self._key("absent-2", ref),
                action=Action.DELETE,
                source_record_ref=ref,
            )
        )
        assert first.outcome == "APPLIED"
        assert again.outcome == "ALREADY_ABSENT" and again.replayed is False

    def check_evidence_matches_receipt(self) -> None:
        ref = self.t.disposable_refs[0]
        result = self.c.execute_action(
            ActionRequest(
                idempotency_key=self._key("replay", ref),
                action=Action.DELETE,
                source_record_ref=ref,
            )
        )
        evidence = self.c.get_evidence(EvidenceRequest(receipt_id=result.receipt_id))
        assert (evidence.receipt_id, evidence.idempotency_key, evidence.source_record_ref) == (
            result.receipt_id,
            result.idempotency_key,
            result.source_record_ref,
        )

    # -- hostile input -------------------------------------------------------------------

    def check_malformed_requests_rejected(self) -> None:
        if self.t.raw_post is None:
            return
        ident = {"type": IdentifierType.EMAIL.value, "value": "x@example.in"}
        bad_bodies: list[tuple[str, Any]] = [
            ("/discover", {"identifiers": []}),
            ("/discover", {"identifiers": [ident], "unexpected": True}),
            ("/discover", {"identifiers": [ident] * 21}),
            ("/discover", {"identifiers": [ident], "page_size": 10_000}),
            ("/discover", "not-json"),
            (
                "/actions",
                {"idempotency_key": "short", "action": "DELETE", "source_record_ref": "x"},
            ),
            (
                "/actions",
                {"idempotency_key": "a" * 64, "action": "DROP_TABLE", "source_record_ref": "x"},
            ),
        ]
        for path, body in bad_bodies:
            code = self.t.raw_post(path, body, True)
            assert 400 <= code < 500, f"{path} accepted a malformed body ({code})"

    def check_requires_authentication(self) -> None:
        if self.t.raw_post is None:
            return
        body = {"identifiers": [i.model_dump() for i in self.t.matching]}
        assert self.t.raw_post("/discover", body, False) == 401, "unauthenticated call allowed"

    # Read-only checks first: the action checks destroy the disposable records.
    ORDER = (
        "check_connection",
        "check_requires_authentication",
        "check_malformed_requests_rejected",
        "check_pagination_is_complete_and_stable",
        "check_non_matching_identifiers_find_nothing",
        "check_fingerprints_are_stable",
        "check_duplicate_key_replay",
        "check_concurrent_same_key_applies_once",
        "check_new_key_on_absent_record",
        "check_evidence_matches_receipt",
    )

    def run_all(self) -> dict[str, str]:
        declared = {n for n in dir(self) if n.startswith("check_")}
        assert declared == set(self.ORDER), "every check must appear in ORDER"
        failures: dict[str, str] = {}
        for name in self.ORDER:
            try:
                getattr(self, name)()
            except AssertionError as exc:
                failures[name] = str(exc) or "assertion failed"
            except Exception as exc:  # a crash is a conformance failure too
                failures[name] = f"{type(exc).__name__}: {exc}"
        return failures
