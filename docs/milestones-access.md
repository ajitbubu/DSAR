# Milestone Plan — Right to Access (DPDP s.11)

The second executable right. It reuses intake, OTP verification, jurisdiction, identity resolution, discovery, maker-checker approval, the audit chain and evidence. What's new: **exporting record content**, a **disclosure review** (withholding other people's data), and **secure delivery** of a report to the requester.

## Design decisions (proposed)

- **Nothing personal is kept longer than delivery needs.** Exported content lives only inside an encrypted access report (tenant key, AES-GCM envelope) in private object storage. It never goes into DB rows, logs, the audit trail or the staff evidence package, which records hashes of what was disclosed rather than the content. The report's lifetime after delivery is a new decision, D-25.
- **Disclosure is reviewed and approved.** Misdisclosure is irreversible, so access uses the same maker-checker as erasure: an analyst excludes third-party data with a documented reason, and a separate approver authorises the disclosure set (bound to a hash).
- **The pack decides what happens after discovery.** The worker runs retention evaluation only if the case's workflow defines `RETENTION_EVALUATED` from `DISCOVERY_COMPLETE`. No regulation- or right-specific branches enter handler code.
- **A new pack version, not an edit.** `DPDP@1.1.0` makes ACCESS executable with an `access` workflow. `DPDP@1.0.0` stays published and immutable; cases decided under it stay pinned to it.

## A1 — Export plumbing and pack 1.1.0 ✅

- The connector SDK gains `export_records`: a bounded wire model (≤50 records per call, ≤200 fields per record, ≤2,000 chars per value, 2 MB response cap) and `POST {base}/export` in `http_v1`.
- Mock connectors implement export (only for records in that account, unknown refs omitted), and the conformance kit gains export checks.
- `DPDP@1.1.0`: ACCESS is executable with the `access` workflow, and there's a new exception code `THIRD_PARTY_DATA`. Access guards that A2 implements fail closed until then.
- The worker's post-discovery step is pack-driven.

**Acceptance**
- Both mocks pass the extended conformance kit. A deliberately broken exporter (returns unrequested records) is flagged.
- An ACCESS case under 1.1.0 goes verified → jurisdiction (workflow `access`) → discovery → `DISCOVERY_COMPLETE`, with **no** retention decisions created.
- An ERASURE case under 1.1.0 behaves exactly as under 1.0.0. All existing erasure tests pass unchanged.
- 1.0.0 still loads and verifies; the manifest pins both versions; the architecture test is still green.

## A2 — Disclosure review and approval ✅

- Export at review time into an encrypted draft. The analyst sees records and fields and excludes fields or records with a reason code (append-only). A processing summary comes from a tenant-maintained processing register (purposes, recipients per connector or category, covering s.11(1)(b) "other fiduciaries/processors").
- The approver authorises the disclosure set (hash-bound, same maker-checker rules as erasure).

**Acceptance**
- Excluded content never reaches the report. Every exclusion needs a reason from the pack vocabulary. A changed disclosure set invalidates an approval (409). The analyst can't approve their own set (403).
- DB rows, logs and audit details contain no exported values (scans extended).

**As built**
- `POST /v1/cases/{id}/disclosure/exports` starts an export round (only for an ACCESS case, only while it's `UNDER_REVIEW`). The worker (`case.export_requested`) calls `export_records` per connector in batches of 50, outside any transaction, and stores the bundle as a single AES-GCM envelope under the tenant key in private object storage. `disclosure_export` holds status, counts and the content SHA-256. Records deleted since discovery are listed as missing. A new round resets exclusions.
- `GET /v1/cases/{id}/disclosure` is the only way to see exported content. It needs the new `disclosure:read` permission (analysts and approvers, not auditors or admins), every read is audited, and responses are sent `Cache-Control: no-store`.
- `POST /v1/cases/{id}/disclosure/exclusions` withholds or restores a record or a field. It's append-only (`disclosure_exclusion`, where the latest row per record and field wins), and reasons must come from the pinned pack's exception codes.
- Processing register: `GET /v1/processing-register` and `POST /v1/processing-register/{connector}` (new `register:manage` permission, tenant admin). It's append-only, and each change is a new version.
- The `disclosure_reviewed` guard needs a READY latest export and a register entry for every connector the case found data in.
- The approval hash now also covers the export hash, the exclusions and the register versions. It's unchanged for cases without a disclosure. Exclusion authors can't approve.
- An approved access case stays `APPROVED`. A3 builds the report from there instead of erasure fulfilment.
- UI: the case's Disclosure tab, a disclosure summary on the approval page, and `/ops/register`. Playwright spec `e2e/access-disclosure.spec.ts`. The requester-facing choice of right arrives in A3, so the spec submits the request through the public API.

## A3 — Report delivery to the requester ✅

- Build the approved report (JSON plus a readable HTML rendering), encrypt it and store it privately. The requester downloads it through the existing tracking session (BFF-streamed, audited, download-count and expiry limits).
- The staff evidence package records disclosure hashes, approvals and delivery events, without content. The completion response and case closure work as for erasure.
- UI: the request form offers "Get a copy of my data". There's a requester download screen, and staff screens for the disclosure review and approval. The end-to-end Playwright test covers ACCESS.

**Acceptance**
- The requester can download only their own report, only within its validity, and only through a live session. Cross-session and cross-tenant access get 404, and expiry gets 410.
- The report decrypts only with the tenant key. The stored object isn't readable plaintext.
- Full ACCESS end-to-end in Playwright. `make logscan` and the PII scans stay clean.

**As built**
- On approval of a case with a disclosure, the approval transaction fires `START_FULFILMENT` and queues `case.report_requested`. The worker builds the report from the approved export, with exclusions applied and the processing summary from the register. It renders JSON plus self-contained, script-free, escaped HTML, encrypts each under the tenant key, and stores them privately (`access_report`). The staff evidence package is then built with a new `disclosure.json` (export hashes, the exclusion history, register versions, report hashes, no content), which fires `REPORT_READY`. The completion message and closure follow the erasure path. The message has counts and dates only.
- The requester downloads with `GET /v1/public/case/report/{json|html}` over their tracking session. Each download is counted atomically and audited. Expiry, the download limit or a purge gives 410. Responses are attachments with `no-store` and `nosniff`, and HTML gets `CSP: sandbox`. The status page shows availability and downloads left. The app role can update only `download_count` and `purged_at`.
- **Returning sign-in** (needed because sessions last at most 24 hours): `POST /v1/public/sessions` with reference and contact always answers the same way, and sends a code only when both match a verified request. It's rate limited per IP and per contact. The resulting `SIGN_IN` challenge opens a new session without touching case state, and a lockout doesn't fail the case.
- `make purge-reports` (run it daily) deletes the objects of expired or used-up reports. `BlobStore.delete` was added for it.
- UI: the request form asks "Delete my data" or "Get a copy of my data", there's a "Return to your request" page, download buttons on the status page, and report status on the staff Disclosure tab. Playwright: `e2e/access-end-to-end.spec.ts`.
- D-25 and D-26 run on their stated defaults (14 days, 5 downloads; JSON plus accessible HTML, in English) until decided.

## New open decisions

| ID | Decision | Default until decided |
|---|---|---|
| D-25 | How long the access report stays available, and how many downloads are allowed | 14 days, 5 downloads, then deleted |
| D-26 | Format of the requester-facing report (JSON only, HTML, PDF), and accessibility and language needs | JSON plus accessible HTML, in English |
| D-27 | Who maintains the processing register, and how it's evidenced (s.11(1)(b)) | Tenant admin edits it in the console |
