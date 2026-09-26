# ADR-0007: Evidence storage

- Status: Proposed. **Evidence retention period, WORM/Object Lock, and download mechanism are open decisions D-4 / D-8.**
- Date: 2026-09-25

## Decision
- **S3-compatible object storage** behind a `BlobStore` interface. SeaweedFS (S3 gateway) in local dev, because MinIO images are no longer published. The production backend is TBD.
- One **private** bucket. No public ACLs or policy. Not routed through `web` static paths. Keys are `tenants/{tenant_id}/requests/{request_id}/{artifact_uuid}` (opaque, no PII, no original filenames).
- Server-side encryption enabled (SSE-S3 in dev; production SSE-KMS depends on D-3). Package contents that include identifiers are additionally envelope-encrypted at the application layer.
- `EvidenceArtifact` row per object: `sha256`, `size_bytes`, `media_type`, `kind`, `retain_until` (nullable until D-4).
- **Evidence package** = a ZIP containing:
  - `manifest.json`: case summary (masked identifiers), pack id@version, per-artifact SHA-256
  - connector receipts
  - verification report
  - retention decisions with exception reasons
  - approvals
  - redacted audit timeline
  - `manifest.sha256`

  The manifest hash is recorded in the audit chain. Signing the manifest with a KMS asymmetric key is designed in but depends on D-3.
- **Download:** streamed through the API after authz (`AUDITOR`, `PRIVACY_ANALYST`, `APPROVER` of the tenant), with `Content-Disposition: attachment` and `nosniff`. Each download is audited. No presigned URLs in v1, so no bearer tokens appear in URLs (D-8).
- **Uploads** (supporting docs): size limit, extension + MIME + magic-byte allowlist validated server-side before storage, server-generated key. AV scanning depends on D-10.

## Consequences
+ Evidence is tamper-evident (hash in manifest + audit chain) and never publicly reachable.
− Streaming through the API costs API bandwidth. That's acceptable at DSAR volumes.
