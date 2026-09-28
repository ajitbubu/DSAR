export const STATUS_LABEL: Record<string, string> = {
  PENDING_VERIFICATION: "Awaiting verification",
  VERIFICATION_FAILED: "Verification failed",
  VERIFIED: "Verified",
  JURISDICTION_DETERMINED: "Jurisdiction set",
  DISCOVERY_IN_PROGRESS: "Discovering",
  DISCOVERY_COMPLETE: "Discovery complete",
  RETENTION_EVALUATED: "Ready for review",
  UNDER_REVIEW: "Under review",
  PENDING_APPROVAL: "Awaiting approval",
  APPROVED: "Approved",
  REJECTED: "Returned for rework",
  FULFILMENT_IN_PROGRESS: "Fulfilment running",
  VERIFICATION_IN_PROGRESS: "Verifying outcome",
  RECONCILIATION_REQUIRED: "Needs reconciliation",
  VERIFIED_COMPLETE: "Verified",
  EVIDENCE_GENERATED: "Evidence ready",
  RESPONDED: "Requester notified",
  PENDING_MANUAL_HANDLING: "Manual handling",
  CANCELLED: "Withdrawn",
  CLOSED: "Closed",
};

export function statusTone(status: string): string {
  if (["VERIFICATION_FAILED", "RECONCILIATION_REQUIRED"].includes(status)) return "status bad";
  if (["DISCOVERY_COMPLETE", "CLOSED", "VERIFIED_COMPLETE", "SUCCEEDED"].includes(status)) {
    return "status ok";
  }
  if (["FAILED", "FAILED_FINAL"].includes(status)) return "status bad";
  if (status === "FAILED_RETRYABLE") return "status warn";
  return "status";
}

export function when(iso: string | null): string {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short",
                                            timeZone: "Asia/Kolkata" }).format(new Date(iso));
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export const DECISION_LABEL: Record<string, string> = {
  DELETE: "Delete",
  RETAIN: "Retain",
  RESTRICT: "Restrict",
  ANONYMIZE: "Anonymise",
  MANUAL_REVIEW: "Needs review",
};

export function decisionTone(decision: string): string {
  if (decision === "DELETE") return "status bad";
  if (decision === "MANUAL_REVIEW") return "status warn";
  if (decision === "RETAIN") return "status ok";
  return "status";
}

export const SLA_LABEL: Record<string, string> = {
  UNVALIDATED: "Deadline not validated",
  ON_TRACK: "On track",
  DUE_SOON: "Due soon",
  OVERDUE: "Overdue",
  DONE: "Done",
  NOT_APPLICABLE: "—",
};

export function slaTone(state: string): string {
  if (state === "OVERDUE") return "status bad";
  if (state === "DUE_SOON" || state === "UNVALIDATED") return "status warn";
  if (state === "DONE" || state === "ON_TRACK") return "status ok";
  return "status";
}
