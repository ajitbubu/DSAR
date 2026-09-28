"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

export function LegalHoldForm({ caseId }: { caseId: string }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [scope, setScope] = useState<"CASE" | "DATA_PRINCIPAL">("DATA_PRINCIPAL");
  const [matter, setMatter] = useState("");
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!csrf) return;
    const r = await staffPost("/v1/legal-holds", csrf,
                              { scope, case_id: caseId, matter_ref: matter.trim(), reason: reason.trim() });
    if (r.ok) {
      setMessage({ ok: true, text: "Legal hold placed. Records in scope are now retained." });
      setMatter("");
      setReason("");
      router.refresh();
    } else if (r.status === 403) {
      setMessage({ ok: false, text: "Your role can't place legal holds." });
    } else {
      setMessage({ ok: false, text: "Check the matter reference and give a reason of at least 10 characters." });
    }
  }

  return (
    <form className="decision-form" onSubmit={submit} noValidate>
      {message && <div className={message.ok ? "alert success" : "alert error-box"} role="status">{message.text}</div>}
      <label>
        <span className="legend">Applies to</span>
        <select value={scope} onChange={(e) => setScope(e.target.value as typeof scope)}>
          <option value="DATA_PRINCIPAL">All requests from this person</option>
          <option value="CASE">This request only</option>
        </select>
      </label>
      <label htmlFor="matter" className="legend">Matter reference</label>
      <input id="matter" type="text" maxLength={64} value={matter} onChange={(e) => setMatter(e.target.value)} />
      <label htmlFor="hold-reason" className="legend">Reason</label>
      <textarea id="hold-reason" maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)} />
      <div className="actions"><button type="submit" disabled={!csrf}>Place legal hold</button></div>
    </form>
  );
}
