# ID-PRIVACY DPAR/DSAR Automation — Product Scope

## 1. Objective

A DPDP-first, globally configurable platform. It receives Data Principal (DPDP) or Data Subject (GDPR and others) rights requests, then:

1. verifies identity
2. works out which regulatory rules apply
3. discovers personal data across connected systems
4. applies retention and exception policy
5. orchestrates fulfilment under maker-checker control
6. verifies the outcome
7. produces auditable evidence

## 2. Personas

| Persona | Authn | Capabilities |
|---|---|---|
| **Data Principal (DP)** | No account. OTP-verified, case-scoped tracking session. | Submit a request, verify identity, track status, receive the completion response. |
| **Privacy Analyst** | Staff SSO (OIDC) | Triage cases, review discovery results, confirm or override retention decisions with a reason, submit for approval. |
| **Approver** (e.g. DPO) | Staff SSO (OIDC) | Approve or reject destructive actions. Can't approve a case where they were the reviewing analyst. |
| **Auditor** | Staff SSO (OIDC) | Read-only access to cases, audit timeline and evidence. |
| **Tenant Admin** | Staff SSO (OIDC) | Manage users and roles, connectors, and the policy-pack version in use. No case-data access unless also granted an analyst role. |
| **Platform Operator** | Separate ops plane | Deploys and runs the platform. **No** tenant-data access by default. |

## 3. In scope — first release (Right to Erasure vertical slice)

End-to-end, executable:

1. DP submits an erasure request (web form).
2. Platform issues a case ID (non-guessable display ID, e.g. `DPR-2026-7K4Q9M`, plus an internal UUID).
3. DP verifies identity with a **mock OTP provider**.
4. Jurisdiction decision loads a **versioned DPDP policy pack**.
5. Identity resolution produces a canonical identifier set (normalised email, E.164 phone, customer IDs).
6. Two **mock connectors** (CRM, Document Store) run discovery.
7. Matches are shown per source.
8. The retention engine gives every match exactly one of: `DELETE`, `RETAIN`, `RESTRICT`, `ANONYMIZE`, `MANUAL_REVIEW`.
9. `RETAIN` (and any analyst override) requires a documented exception reason from a controlled vocabulary, plus free text.
10. Analyst review.
11. A separate Approver authorises eligible destructive actions.
12. The orchestrator dispatches idempotent actions to the connectors.
13. Connectors return execution evidence.
14. Rescan verifies the outcome (deleted records absent, anonymised records carry no identifiers, retained or restricted records match their decision).
15. A downloadable evidence package (signed manifest plus artifacts) is generated.
16. The DP receives a completion response. The mock channel records it as a `Communication`.
17. The case closes only when every `FulfilmentTask` is in a terminal status.

### Rights catalogue (DPDP pack v1)

| Right (DPDP Act 2023 reference) | Status in v1 |
|---|---|
| Erasure (s.12) | **Executable workflow** |
| Access to information about processing (s.11) | Registered, placeholder workflow |
| Correction, completion, updating (s.12) | Registered, placeholder workflow |
| Consent withdrawal (s.6(4)) | Registered, placeholder workflow |
| Grievance redressal (s.13) | Registered, placeholder workflow |
| Nomination (s.14) | Registered, placeholder workflow |

Submitting a placeholder right creates a case in `PENDING_MANUAL_HANDLING`. Nothing is automated.

### UIs (12)

DP request form · OTP verification · confirmation and tracking · ops dashboard · case details · discovery results · retention review · approval queue · fulfilment execution · verification and reconciliation · evidence package · audit timeline.

## 4. Out of scope — first release

- Executable workflows for rights other than erasure.
- Real connectors (Salesforce, SharePoint, S3, databases). Only the SDK and two mocks are built.
- Real OTP delivery (SMS or email provider). Only the mock provider is built.
- Policy packs other than DPDP (GDPR, UK GDPR, CCPA/CPRA, US states, LGPD, Singapore PDPA). The architecture must accommodate them. None are authored.
- Kubernetes, cloud IaC, multi-region. Production deployment is documented only.
- Consent manager integration, nominee authentication, guardian (child/PwD) verification flows.
- Self-service tenant onboarding and billing.
- Automated legal-hold ingestion from eDiscovery tools. Legal holds are entered manually by staff.

## 5. Non-functional requirements

| Area | Requirement |
|---|---|
| Security | See `threat-model/threat-model.md`. Server-side authz on every protected operation. Tenant isolation. Maker-checker. Append-only audit. |
| Privacy | Data minimisation: the platform stores **pointers and hashes** of discovered records, not full record copies. PII fields are encrypted at the application layer. Structured logs are redacted. |
| Correctness | Connector actions are idempotent. Retries never duplicate destructive actions. State transitions are explicit and validated. |
| Auditability | Every state transition, decision, approval and connector call produces an `AuditEvent`. The evidence package is tamper-evident (hash manifest). |
| Configurability | Regulation rules, rights, SLAs, verification strength and retention rules live in versioned policy packs, not in handlers. |
| Testability | Pytest (unit, integration, negative security), Vitest (web units), Playwright (full erasure slice end-to-end). |

## 6. Success criteria for the first release

- A Playwright test drives an erasure request from submission to `CLOSED` against Docker Compose, with two mock connectors, and downloads the evidence package.
- The negative test suite covers unauthenticated, wrong-role, cross-tenant, IDOR, malformed, replayed (OTP, idempotency and approval replay) and oversized requests.
- Replaying an approved fulfilment dispatch N times produces exactly one destructive call per record at the connector.
- No PII appears in application logs during the E2E run. A log-scan test asserts this.

## 7. Glossary

- **Data Principal** — DPDP term for the individual the data relates to. Equivalent to GDPR's Data Subject.
- **Policy pack** — versioned, immutable bundle of rights, workflows, SLAs, verification rules and retention/exception rules for one regulation.
- **Match** — a pointer to one record, in one source system, that relates to the requester.
- **Terminal status** — `SUCCEEDED`, `FAILED_FINAL`, `SKIPPED` (with reason) or `CANCELLED`.
