"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

type Props = { caseId: string; version: number; digest: string };

export function ApprovalForm({ caseId, version, digest }: Props) {
  const router = useRouter();
  const csrf = useCsrfToken();
  // One key per rendered decision: a double click or a retried request can't decide twice.
  const key = useMemo(() => crypto.randomUUID().replaceAll("-", ""), []);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function decide(outcome: "APPROVED" | "REJECTED") {
    if (!csrf) return;
    if (outcome === "REJECTED" && comment.trim().length < 10) {
      setError("Explain what needs to change (at least 10 characters).");
      return;
    }
    setBusy(true);
    setError(null);
    const r = await staffPost(`/v1/cases/${caseId}/approvals`, csrf, {
      outcome, case_version: version, decision_set_sha256: digest,
      ...(comment.trim() ? { comment: comment.trim() } : {}),
    }, { "Idempotency-Key": `${key}-${outcome.toLowerCase()}` });
    setBusy(false);
    if (r.ok) router.refresh();
    else setError(r.title ?? "That didn't work.");
  }

  return (
    <div className="decision-form">
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <label htmlFor="approval-comment" className="legend">Comment (required to reject)</label>
      <textarea id="approval-comment" maxLength={2000} value={comment}
                onChange={(e) => setComment(e.target.value)} />
      <p className="hint mono">Decision set {digest.slice(0, 12)}… · version {version}</p>
      <div className="actions">
        <button type="button" onClick={() => decide("APPROVED")} disabled={busy || !csrf}>Approve</button>
        <button type="button" className="danger" onClick={() => decide("REJECTED")} disabled={busy || !csrf}>
          Reject
        </button>
      </div>
    </div>
  );
}
