export const STATUS_LABEL: Record<string, string> = {
  PENDING_VERIFICATION: "Awaiting verification",
  VERIFICATION_FAILED: "Verification failed",
  VERIFIED: "Verified",
  JURISDICTION_DETERMINED: "Jurisdiction set",
  DISCOVERY_IN_PROGRESS: "Discovering",
  DISCOVERY_COMPLETE: "Discovery complete",
  PENDING_MANUAL_HANDLING: "Manual handling",
  CANCELLED: "Withdrawn",
  CLOSED: "Closed",
};

export function statusTone(status: string): string {
  if (["VERIFICATION_FAILED", "RECONCILIATION_REQUIRED"].includes(status)) return "status bad";
  if (["DISCOVERY_COMPLETE", "CLOSED", "VERIFIED_COMPLETE", "SUCCEEDED"].includes(status)) {
    return "status ok";
  }
  if (status === "FAILED") return "status bad";
  return "status";
}

export function when(iso: string | null): string {
  if (!iso) return "—";
  return new Intl.DateTimeFormat("en-IN", { dateStyle: "medium", timeStyle: "short",
                                            timeZone: "Asia/Kolkata" }).format(new Date(iso));
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
