# Anonymisation and Pseudonymisation

The platform handles personal data in two separate places, and each gets different protection:

- **Source systems** (CRM, billing and so on) hold the data subject's records. When a retention decision says `ANONYMIZE`, the platform tells the source system's connector to anonymise the record and then checks the result. The platform never anonymises source data itself.
- **The platform's own store** keeps the case: the requester's name, identifiers, pointers to matched records, and evidence. This data is pseudonymised. Values are encrypted, and lookups use keyed hashes (blind indexes). Staff and evidence only ever see masked values. After a case closes and its grace period passes, this data is shredded (D-12).

Key custody (D-3) is HashiCorp Vault Transit in production and a derived local key in dev/test.

## 1. Overview

```mermaid
flowchart LR
  subgraph DP[Data subject]
    F[Request form<br/>name, email, phone]
  end

  subgraph PLAT[Platform store — pseudonymised]
    direction TB
    INT[Intake<br/>intake/service.py]
    ENC[(enc_* columns<br/>AES-256-GCM envelope)]
    BIDX[(bidx_* columns<br/>HMAC-SHA256)]
    MATCH[(data_match<br/>pointer + fingerprint,<br/>never content)]
    MASK[Masking<br/>identity/masking.py]
    RED[Redaction<br/>platform/logging.py]
    EVD[(Evidence package<br/>masked + hashed)]
    AUD[(Audit chain<br/>redacted details)]
    PURGE["Post-closure minimiser (D-12)<br/>minimisation/service.py"]
  end

  subgraph KEYS[Key custody — D-3]
    KP["KeyProvider<br/>VaultTransitKeyProvider (prod)<br/>LocalKeyProvider (dev/test)"]
  end

  subgraph SRC[Source systems — anonymised on decision]
    CON[Connector<br/>execute_action ANONYMIZE]
    REC[(Source record)]
  end

  F --> INT
  INT -->|encrypt| ENC
  INT -->|keyed hash| BIDX
  KP -. wrap / unwrap DEK .-> ENC
  KP -. HMAC .-> BIDX
  ENC -->|decrypt for discovery| CON
  CON -->|pointers only| MATCH
  ENC -->|decrypt then mask| MASK --> EVD
  RED --> AUD
  CON -->|strip identifiers + content| REC
  PURGE -. shred after grace period .-> ENC
  PURGE -. drop .-> BIDX
```

## 2. Pseudonymisation: the key hierarchy

Every `enc_*` value has its own data key (DEK). The DEK is wrapped by the tenant's key (KEK). The tenant id and the column context are bound into the encryption as associated data, so a ciphertext fails to decrypt if it is moved to another tenant or column. The blind-index key is a separate per-tenant key, so a stolen table of hashes can't be checked against guessed emails or phone numbers without that key.

With Vault Transit, neither key ever leaves Vault. The platform sends the DEK to Vault to be wrapped and unwrapped, and sends the identifier to Vault to be HMAC'd. The `key_id` in each ciphertext (`local-1` or `vault`) records which provider wrapped it.

```mermaid
flowchart TB
  subgraph Dev["LocalKeyProvider — dev/test only"]
    MK[Master key<br/>IDP_LOCAL_MASTER_KEY] -->|HKDF 'kek:tenant'| KEK1[Tenant KEK]
    MK -->|HKDF 'bidx:tenant'| BK1[Tenant blind-index key]
  end

  subgraph Prod["VaultTransitKeyProvider — production (D-3)"]
    V[Vault Transit engine] --> KEK2["idp-kek-&lt;tenant&gt;<br/>non-exportable, rotatable"]
    V --> BK2["idp-bidx-&lt;tenant&gt;<br/>non-exportable, pinned to v1"]
  end

  KEK1 & KEK2 -->|wrap| DEK[Per-value DEK<br/>AES-256-GCM]
  DEK --> CT["v1.key_id.wrapped_dek.nonce.ct<br/>AAD = tenant_id | context"]
  BK1 & BK2 -->|HMAC kind:normalised_value| IDX[bidx hex digest]
```

| Pseudonymised field | Encrypted column | Blind index | Code |
|---|---|---|---|
| Data subject identifiers | `data_principal.enc_identifiers` | `bidx_email`, `bidx_phone` | [intake/service.py](../../apps/api/src/idprivacy/domain/intake/service.py) |
| Name, submitted identifiers | `privacy_request.enc_full_name`, `enc_submitted_identifiers` | — | intake/service.py |
| Request details | `request_right.enc_details` | — | intake/service.py |
| Resolved identifiers | `request_identifier.enc_value` | `request_identifier.bidx` | [identity/resolution.py](../../apps/api/src/idprivacy/domain/identity/resolution.py) |
| OTP | — | `challenge_hash` (keyed HMAC) | [identity/verification.py](../../apps/api/src/idprivacy/domain/identity/verification.py) |
| Staff email | `app_user.enc_email` | — | seed / OIDC |
| Disclosure export, access report | encrypted blob | — | [disclosure/](../../apps/api/src/idprivacy/domain/disclosure/) |
| Session token | — | `token_hash` (SHA-256) | [dp_session.py](../../apps/api/src/idprivacy/platform/auth/dp_session.py) |

Operations:

- Set `IDP_KEY_PROVIDER=vault`, `IDP_VAULT_ADDR` (https outside local/test), `IDP_VAULT_TOKEN` and optionally `IDP_VAULT_TRANSIT_MOUNT`.
- Run `make vault-provision` after adding a tenant. It is safe to repeat.
- The KEK can be rotated in Vault at any time. **Never rotate `idp-bidx-*`:** every stored blind index would stop matching.
- If Vault is unreachable, calls raise `KeyServiceError`, not `DecryptionError`, so an outage is never mistaken for tampered data.

Code: [platform/crypto.py](../../apps/api/src/idprivacy/platform/crypto.py), [runtime.py](../../apps/api/src/idprivacy/runtime.py) (`build_keys`), [scripts/vault_provision.py](../../apps/api/src/idprivacy/scripts/vault_provision.py).

## 3. Anonymisation: from decision to verification

```mermaid
sequenceDiagram
  autonumber
  participant P as Policy pack
  participant R as Retention engine
  participant S as Staff reviewer
  participant A as Approver
  participant F as Fulfilment
  participant C as Connector
  participant V as Verification

  P->>R: retention_rules (DPDP 1.2.0: support history → ANONYMIZE)
  R->>R: one decision per data_match, first rule wins
  S->>R: may override any decision to ANONYMIZE
  R->>A: decision set (sha256-bound)
  A-->>F: approved
  F->>C: execute_action(ANONYMIZE, source_record_ref, idempotency_key)
  Note over C: The connector decides which fields<br/>to strip (connector-defined)
  C-->>F: ActionResult (observed=ANONYMIZED)
  F->>V: verify
  V->>C: verify_action → ANONYMIZED
  V->>C: rescan with verified identifiers
  C-->>V: record not found
  V-->>F: PASS only if ANONYMIZED and not in rescan
```

Code: [fulfilment/service.py](../../apps/api/src/idprivacy/domain/fulfilment/service.py) (dispatch), [verification/service.py](../../apps/api/src/idprivacy/domain/verification/service.py) (`judge`), [mock_connectors/app.py](../../packages/mock-connectors/src/mock_connectors/app.py) (reference behaviour), [dpdp/1.2.0/pack.yaml](../../packages/policy-packs/dpdp/1.2.0/pack.yaml) (`support-history-anonymise`).

The platform doesn't define which fields a connector must remove. The rescan is the only check: after anonymisation, the record must no longer match the requester's identifiers.

## 4. Post-closure minimisation (D-12)

After a case closes, the platform keeps only what the evidence needs. Once the pinned pack's `post_closure_retention_days` has passed (default 30), `make minimise-closed` shreds the case's personal data. A legal hold blocks it if it covers the case, the data principal, or a connector or record type the case touched.

```mermaid
stateDiagram-v2
  [*] --> Active: intake
  Active --> Closed: case closed or cancelled
  Closed --> Closed: grace period (pack-configured)
  Closed --> Held: legal hold active
  Held --> Closed: hold released
  Closed --> Minimised: minimise-closed job
  state Minimised {
    [*] --> shred: enc_* set to NULL (DEK gone = crypto-shred)
    shred --> drop: request_identifier rows deleted,<br/>sessions revoked, export/report blobs deleted
    drop --> principal: data_principal shredded once<br/>none of their requests needs it
  }
  Minimised --> [*]
```

What survives minimisation: case ids, dates, the rights exercised, masked identifiers inside the evidence package, record pointers (`source_record_ref`, `content_fingerprint`), decisions, approvals, verification results and the audit hash chain. None of these can be read back to a person without the source system.

After minimisation, a returning sign-in or OTP resend for that case acts as if no case matches, and the staff disclosure view opens without the deleted export.

Code: [minimisation/service.py](../../apps/api/src/idprivacy/domain/minimisation/service.py), [scripts/minimise_closed.py](../../apps/api/src/idprivacy/scripts/minimise_closed.py), migration [0012_minimisation.py](../../apps/api/migrations/versions/0012_minimisation.py).
