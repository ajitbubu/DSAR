"""Every threat in docs/threat-model/threat-model.md §3 maps to tests that exist (M9).

If a referenced test is renamed or deleted, this fails, so the threat model can't
silently drift away from what's actually tested.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
API_TESTS = REPO / "apps/api/tests"

# threat id -> "path::test_name" (Python) or a path (TypeScript / scripts)
COVERAGE: dict[str, list[str]] = {
    "T-01": [
        "test_jurisdiction_pipeline.py::test_pipeline_is_idempotent_and_skips_unverified",
        "test_discovery.py::test_only_verified_identifiers_are_sent_to_connectors",
        "test_discovery.py::test_claimed_customer_id_is_never_used_for_discovery",
    ],
    "T-02": [
        "test_otp_verification.py::test_five_wrong_attempts_lock_the_challenge",
        "test_otp_verification.py::test_concurrent_guesses_are_counted_exactly",
        "test_otp_verification.py::test_expired_code_is_410",
    ],
    "T-03": ["test_otp_verification.py::test_replayed_challenge_is_409"],
    "T-04": [
        "test_dp_session.py::test_display_id_alone_grants_nothing",
        "test_dp_session.py::test_missing_or_bogus_session_is_401",
    ],
    "T-05": [
        "test_logging_redaction.py::test_structlog_redacts_sensitive_keys_and_values",
        "apps/web/e2e/dp-intake.spec.ts",
        "infra/compose/logscan.sh",
    ],
    "T-06": ["apps/web/lib/server/csrf.test.ts", "apps/web/app/api/public/requests/route.test.ts"],
    "T-07": ["apps/web/lib/csp.test.ts"],
    "T-08": [
        "security/test_authz_matrix.py::test_other_tenants_never_reach_a_case",
        "security/test_authz_matrix.py::test_users_without_roles_are_forbidden_everywhere",
    ],
    "T-09": [
        "test_rls.py::test_unfiltered_query_only_sees_current_tenant",
        "test_rls.py::test_composite_fk_blocks_cross_tenant_reference",
        "security/test_authz_matrix.py::test_collections_never_list_other_tenants",
    ],
    "T-10": [
        "test_jwt_validation.py::test_alg_none_rejected",
        "test_jwt_validation.py::test_hs256_key_confusion_rejected",
    ],
    "T-11": [
        "test_approvals.py::test_submitter_cannot_approve_even_with_approver_role",
        "test_approvals.py::test_override_author_cannot_approve",
        "test_approvals.py::test_db_rejects_maker_as_checker",
        "test_approvals.py::test_approve_cannot_bypass_maker_checker_via_transitions",
    ],
    "T-12": [
        "test_fulfilment.py::test_five_concurrent_dispatches_apply_once",
        "test_fulfilment.py::test_worker_crash_mid_dispatch_resumes_without_duplication",
        "test_fulfilment.py::test_timeout_after_apply_is_retried_without_a_second_effect",
    ],
    "T-13": [
        "test_discovery.py::test_malformed_or_hostile_connector_responses_are_rejected",
        "test_verification_evidence.py::test_lying_connector_is_caught_and_reconciled",
        "packages/connector-sdk/tests/test_conformance_kit.py",
    ],
    "T-14": [
        "security/test_injection_and_secrets.py::"
        "test_connector_credentials_resolve_by_reference_only"
    ],
    "T-15": [
        "test_crypto.py::test_ciphertext_bound_to_tenant",
        "test_public_intake.py::test_personal_data_and_otp_are_not_stored_in_plaintext",
        "test_discovery.py::test_matches_store_pointers_not_personal_data",
    ],
    "T-16": [
        "test_audit.py::test_verification_detects_tampering",
        "test_audit.py::test_app_role_cannot_mutate_audit_events",
    ],
    "T-17": [
        "test_public_intake.py::test_oversized_streamed_body_is_413",
        "test_public_intake.py::test_rate_limit_per_ip",
    ],
    "T-18": [
        "test_verification_evidence.py::test_invalid_uploads_rejected",
        "test_verification_evidence.py::test_oversized_upload_is_413",
    ],
    "T-19": [
        "test_logging_redaction.py::test_stdlib_logging_is_redacted_too",
        "infra/compose/logscan.sh",
    ],
    "T-20": [
        "test_config.py::test_mock_otp_provider_refused_outside_dev",
        "test_closure.py::test_mock_notifier_refused_outside_dev",
    ],
    "T-22": [
        "test_policy_packs.py::test_tampered_pack_file_is_rejected",
        "test_policy_packs.py::test_registry_detects_tampered_db_row",
    ],
    "T-23": [
        "test_verification_evidence.py::test_package_contains_no_plaintext_personal_data",
        "test_closure.py::test_completion_text_contains_no_personal_data",
    ],
    "T-24": ["test_public_intake.py::test_malformed_input_rejected"],
    "T-25": [
        "security/test_injection_and_secrets.py::test_no_sql_is_built_from_interpolated_strings",
        "security/test_injection_and_secrets.py::test_injection_payloads_are_just_data",
    ],
}
PROCESS_ONLY = {"T-21"}  # operator access: a process control, tracked as decision D-7


def _exists(ref: str) -> bool:
    if "::" in ref:
        path, name = ref.split("::")
        source = API_TESTS / path
        return (
            source.exists()
            and re.search(rf"^def {name}\(", source.read_text(), re.MULTILINE) is not None
        )
    return (REPO / ref).exists()


def test_every_referenced_test_exists() -> None:
    missing = [ref for refs in COVERAGE.values() for ref in refs if not _exists(ref)]
    assert missing == []


def test_every_threat_in_the_model_is_covered() -> None:
    model = (REPO / "docs/threat-model/threat-model.md").read_text()
    threats = set(re.findall(r"^\| (T-\d\d) \|", model, re.MULTILINE))
    assert threats, "no threats parsed from the model"
    assert threats == set(COVERAGE) | PROCESS_ONLY
