"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { DECISION_LABEL } from "../../../_components/labels";
import { staffPost } from "../../../_components/staffPost";

type Props = {
  caseId: string;
  matchId: string;
  currentId: string;
  currentDecision: string;
  decisions: string[];
  codes: { code: string; label: string }[];
};

export function DecisionForm({ caseId, matchId, currentId, currentDecision, decisions, codes }: Props) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [open, setOpen] = useState(false);
  const [decision, setDecision] = useState(currentDecision === "MANUAL_REVIEW" ? "RETAIN" : currentDecision);
  const [code, setCode] = useState(codes[0]?.code ?? "");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (reason.trim().length < 10) {
      setError("Explain the decision in at least 10 characters.");
      return;
    }
    if (!csrf) return;
    setBusy(true);
    const r = await staffPost(`/v1/cases/${caseId}/matches/${matchId}/retention-decisions`, csrf, {
      decision, exception_code: code, exception_reason: reason.trim(), expected_current_id: currentId,
    });
    setBusy(false);
    if (r.ok) {
      setOpen(false);
      setReason("");
      router.refresh();
    } else {
      setError(r.status === 409 ? r.title ?? "The decision changed; reload." : "That didn't work.");
    }
  }

  if (!open) {
    return (
      <button type="button" className="secondary decision-toggle" onClick={() => setOpen(true)}>
        Change decision
      </button>
    );
  }
  const id = `reason-${matchId}`;
  return (
    <form className="decision-form" onSubmit={submit} noValidate>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <div className="row">
        <label>
          <span className="legend">Decision</span>
          <select value={decision} onChange={(e) => setDecision(e.target.value)}>
            {decisions.filter((d) => d !== "MANUAL_REVIEW").map((d) => (
              <option key={d} value={d}>{DECISION_LABEL[d] ?? d}</option>
            ))}
          </select>
        </label>
        <label>
          <span className="legend">Exception basis</span>
          <select value={code} onChange={(e) => setCode(e.target.value)}>
            {codes.map((c) => <option key={c.code} value={c.code}>{c.label}</option>)}
          </select>
        </label>
      </div>
      <label htmlFor={id} className="legend">Reason (recorded in the audit trail)</label>
      <textarea id={id} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} />
      <div className="actions">
        <button type="submit" disabled={busy || !csrf}>Save decision</button>
        <button type="button" className="secondary" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </form>
  );
}
