"""The conformance kit must actually catch broken connectors."""

import secrets
from datetime import UTC, datetime

from idprivacy_connector_sdk import (
    Action,
    ActionRequest,
    ActionResult,
    ConnectionStatus,
    ConnectorDescriptor,
    DiscoveryPage,
    DiscoveryRequest,
    EvidenceBundle,
    EvidenceRequest,
    Identifier,
    IdentifierType,
    Match,
    VerifyRequest,
    VerifyResult,
)
from idprivacy_connector_sdk.testing import ConformanceKit, ConformanceTarget


class NonIdempotentConnector:
    """Applies every call as new and never pages. The kit must flag it."""

    def __init__(self) -> None:
        self.refs = [f"r:{i}" for i in range(3)]
        self.deleted: set[str] = set()

    def test_connection(self) -> ConnectionStatus:
        return ConnectionStatus(
            ok=True,
            descriptor=ConnectorDescriptor(
                connector_id="broken",
                version="0.0.1",
                record_types=["x.y"],
                supported_actions=[Action.DELETE],
                idempotency_retention_days=1,
            ),
        )

    def discover(self, request: DiscoveryRequest) -> DiscoveryPage:
        hits = [] if request.identifiers[0].value.startswith("nobody") else self.refs
        return DiscoveryPage(
            matches=[
                Match(
                    source_record_ref=r,
                    record_type="x.y",
                    data_categories=["contact"],
                    matched_on=[IdentifierType.EMAIL],
                    content_fingerprint="a" * 64,
                )
                for r in hits
            ]
        )

    def execute_action(self, request: ActionRequest) -> ActionResult:
        self.deleted.add(request.source_record_ref)
        return ActionResult(
            idempotency_key=request.idempotency_key,
            receipt_id=f"rcpt_{secrets.token_hex(6)}",
            action=request.action,
            source_record_ref=request.source_record_ref,
            outcome="APPLIED",
            applied_at=datetime.now(UTC),
            replayed=False,
        )

    def verify_action(self, request: VerifyRequest) -> VerifyResult:
        return VerifyResult(source_record_ref=request.source_record_ref, observed="ABSENT")

    def get_evidence(self, request: EvidenceRequest) -> EvidenceBundle:
        raise LookupError("no evidence kept")


def test_kit_flags_a_non_idempotent_connector() -> None:
    target = ConformanceTarget(
        connector=NonIdempotentConnector(),
        matching=[Identifier(type=IdentifierType.EMAIL, value="a@example.in")],
        non_matching=[Identifier(type=IdentifierType.EMAIL, value="nobody@example.in")],
        disposable_refs=["r:0", "r:1", "r:2"],
    )
    failures = ConformanceKit(target).run_all()
    assert {
        "check_pagination_is_complete_and_stable",
        "check_duplicate_key_replay",
        "check_concurrent_same_key_applies_once",
        "check_new_key_on_absent_record",
        "check_evidence_matches_receipt",
    } <= set(failures)
