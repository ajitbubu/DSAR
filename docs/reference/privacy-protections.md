# Privacy protections reference

The platform protects personal data in three ways:

- **Pseudonymisation** inside its own database: values are encrypted, and lookups use keyed hashes.
- **Anonymisation** in source systems, which a connector carries out when a retention decision says `ANONYMIZE`.
- **Post-closure minimisation**, which shreds a case's identifiers once its grace period has passed.

This page lists every setting, command, column and format involved. For why it is built this way, see [Anonymisation and Pseudonymisation](../architecture/anonymisation-pseudonymisation.md).

## Settings

Environment variables use the `IDP_` prefix (`apps/api/src/idprivacy/config.py`). The app refuses to start if validation fails.

| Variable | Type | Default | Effect |
|---|---|---|---|
| `IDP_KEY_PROVIDER` | `local` \| `vault` | `local` | Selects key custody. `local` is refused outside `IDP_ENV` = `local`/`test`. |
| `IDP_LOCAL_MASTER_KEY` | base64, 32 bytes decoded | none | Required when `IDP_KEY_PROVIDER=local`. Per-tenant keys are derived from it with HKDF-SHA256. |
| `IDP_VAULT_ADDR` | URL | none | Required when `IDP_KEY_PROVIDER=vault`. Must start with `https://` outside `local`/`test`. |
| `IDP_VAULT_TOKEN` | secret string | none | Required when `IDP_KEY_PROVIDER=vault`. Sent as `X-Vault-Token`. |
| `IDP_VAULT_TRANSIT_MOUNT` | string | `transit` | Path where the Transit engine is mounted. |

> **Compose gap:** `infra/compose/docker-compose.yml` passes only the variables in its `x-python-env` block. `IDP_KEY_PROVIDER` and `IDP_VAULT_*` aren't in that block, so setting them in your shell or `.env` has no effect on the stack. Pass them with `docker compose run -e`, as shown in [How to set up Vault Transit key custody](../how-to/set-up-vault-key-custody.md).

## Policy-pack field

| Field | Type | Default | Constraint | Effect |
|---|---|---|---|---|
| `post_closure_retention_days` | integer | `30` | 0–3650 | Days a closed case keeps the requester's identifiers before `minimise-closed` shreds them. |

Packs older than DPDP 1.2.0 don't set the field and get the default of 30. A case is judged by the pack it is pinned to. A case with no pinned pack also uses 30.

Retention rules choose `ANONYMIZE` like any other decision (`DELETE`, `RETAIN`, `RESTRICT`, `ANONYMIZE`, `MANUAL_REVIEW`). Rules are checked in order, and the first match wins. A rule can match on `legal_hold`, `identifier_assurance`, `data_categories_any` or `record_types_any`. DPDP 1.2.0 has this rule:

```yaml
- id: support-history-anonymise
  when: { data_categories_any: [support] }
  decision: ANONYMIZE
```

## Commands

| Command | Runs | When | Output | Exit |
|---|---|---|---|---|
| `make minimise-closed` | `python -m idprivacy.scripts.minimise_closed` in the `migrate` image | Daily | `minimised N case(s); M held back by a legal hold` | 0 |
| `make vault-provision` | `python -m idprivacy.scripts.vault_provision` in the `migrate` image | After adding a tenant | `provisioned keys for N tenant(s)` | 0; exits with `IDP_KEY_PROVIDER is not 'vault'; nothing to provision` when the provider is `local` |
| `make purge-reports` | `python -m idprivacy.scripts.purge_reports` | Daily | deletes expired or used-up access reports (D-25) | 0 |

Both scripts need `IDP_DATABASE_URL_MIGRATOR`, which the `migrate` service already has. They list tenants as the migrator role. `minimise-closed` then does each tenant's work as the application role, inside that tenant's row-level security.

## Ciphertext format

```
v1.<key_id>.<wrapped_dek>.<nonce>.<ciphertext>      (base64url, no padding)
```

| Part | Meaning |
|---|---|
| `v1` | Format version. Any other value raises `DecryptionError`. |
| `key_id` | `local-1` (LocalKeyProvider) or `vault` (VaultTransitKeyProvider). A provider refuses another provider's key id. |
| `wrapped_dek` | The per-value 256-bit data key, wrapped by the tenant's KEK. With Vault it holds Vault's own `vault:vN:...` ciphertext. |
| `nonce` | 12 random bytes. |
| `ciphertext` | AES-256-GCM. Associated data is `<tenant_id>\|<context>`. |

Moving a ciphertext to another tenant or column makes decryption fail.

## Encrypted columns and contexts

| Column | Context string | Blind index | Shredded by minimisation |
|---|---|---|---|
| `data_principal.enc_identifiers` | `data_principal.identifiers` | `bidx_email`, `bidx_phone` | yes, once none of the person's requests still needs it |
| `privacy_request.enc_full_name` | `privacy_request.full_name` | none | yes |
| `privacy_request.enc_submitted_identifiers` | `privacy_request.submitted_identifiers` | none | yes |
| `request_right.enc_details` | `request_right.details` | none | yes |
| `request_identifier.enc_value` | `request_identifier.value` | `request_identifier.bidx` | row deleted |
| `app_user.enc_email` | staff email | none | no (staff, not requesters) |

A blind index is `HMAC-SHA256(tenant blind-index key, "<KIND>:<normalised value>")`, written as hex. `KIND` is `EMAIL`, `PHONE` or `CUSTOMER_ID`, and values are normalised first (IDNA, NFC, E.164).

## Key names in Vault

| Key | Type | Exportable | Rotation |
|---|---|---|---|
| `idp-kek-<tenant_id>` | `aes256-gcm96` | no | Allowed at any time. The key version travels inside each wrapped DEK. |
| `idp-bidx-<tenant_id>` | `aes256-gcm96` | no | **Never.** Every HMAC is pinned to `key_version: 1`, and rotating would stop every stored blind index from matching. |

## Masking

Staff screens and the evidence package show identifiers only through `mask()` (`domain/identity/masking.py`):

| Kind | Rule | Example input | Shown as |
|---|---|---|---|
| `EMAIL` | first letter of the local part, first letter of the domain, then the TLD | `priya.sharma@example.in` | `p•••@e•••.in` |
| `PHONE` | first 3 and last 3 characters | `+919876543210` | `+91•••••210` |
| anything else | dots, then the last 2 characters | `CUST-1001` | `•••••••01` |

## What minimisation changes

A case is due when `closed_at + post_closure_retention_days <= now` and `minimised_at` is null. A due case is skipped, and counted as held, while an unreleased legal hold covers any of:

| Hold scope | Matches |
|---|---|
| `CASE` | this case's id |
| `DATA_PRINCIPAL` | this case's data principal |
| `CONNECTOR` | any connector the case's matches came from |
| `RECORD_TYPE` | any record type the case matched |

For each due case that isn't held:

| Effect | Table |
|---|---|
| `enc_full_name`, `enc_submitted_identifiers` set to null; `minimised_at` set | `privacy_request` |
| `enc_details` set to null | `request_right` |
| rows deleted | `request_identifier` |
| open sessions revoked | `dp_session` |
| export blob deleted, `purged_at` set | `disclosure_export` |
| JSON and HTML blobs deleted, `purged_at` set | `access_report` |
| `enc_identifiers`, `bidx_email`, `bidx_phone` set to null; `minimised_at` set (only when none of the person's other requests is still unminimised) | `data_principal` |

Kept on purpose: ids, dates, rights, `data_match` pointers (`source_record_ref`, `content_fingerprint`), decisions, approvals, verification results, the evidence package (masked values only) and the audit chain.

### Audit event

```json
{"action": "request.minimised", "actor_ref": "system:minimisation",
 "details": {"resolved_ids_deleted": 1, "blobs_deleted": 0, "principal_shredded": false}}
```

Audit details go through log redaction (`platform/logging.py`), which replaces the value of any key containing `email`, `phone`, `name`, `otp`, `code`, `token`, `secret`, `password`, `authorization`, `cookie`, `identifier`, `address` or `session` with `[REDACTED]`. Choose detail keys that avoid those words.

### Behaviour after minimisation

| Surface | Behaviour |
|---|---|
| `GET /v1/cases/{id}` | `identifiers: []`, `minimised_at` set. The staff overview says when the identifiers were deleted. |
| Requester returning sign-in, OTP resend | Answers as if no case matches, and no code is sent. |
| Staff disclosure view | Opens, with an empty record list. |

## Errors

| Error | Raised when | Meaning |
|---|---|---|
| `DecryptionError` | wrong version, unknown `key_id`, tampered or moved ciphertext, or Vault answering 400 to a decrypt | The data can't be opened with these keys. |
| `KeyServiceError` | Vault unreachable or answering anything other than 200 (or 204 on provision) | Outage or permission problem, not bad data. |

## Anonymisation in source systems

The platform sends `execute_action(ANONYMIZE, source_record_ref, idempotency_key)` and doesn't decide which fields the connector removes. Verification passes only when the connector reports `ANONYMIZED` **and** a rescan with the requester's verified identifiers no longer finds the record.

The platform doesn't check a connector's `supported_actions` before dispatch. A connector that refuses the action with a 4xx makes the task `FAILED_FINAL` with code `http_<status>`. The mock CRM supports every action. The mock document store supports only `DELETE` and `RESTRICT`.

## Related

- Tutorial: [See privacy protections in action](../tutorials/privacy-protections-walkthrough.md)
- How-to: [How to run post-closure minimisation](../how-to/run-post-closure-minimisation.md)
- How-to: [How to set up Vault Transit key custody](../how-to/set-up-vault-key-custody.md)
- How-to: [How to anonymise a record category instead of deleting it](../how-to/anonymise-instead-of-delete.md)
- Explanation: [Anonymisation and Pseudonymisation](../architecture/anonymisation-pseudonymisation.md)
- Decisions: D-3 and D-12 in [open-decisions.md](../open-decisions.md)
