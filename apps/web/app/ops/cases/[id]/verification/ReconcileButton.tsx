"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

export function ReconcileButton({ caseId }: { caseId: string }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [error, setError] = useState<string | null>(null);
  async function go() {
    if (!csrf) return;
    const r = await staffPost(`/v1/cases/${caseId}/reconcile`, csrf, {});
    if (r.ok) router.refresh();
    else setError(r.status === 403 ? "Your role can't reconcile cases." : r.title ?? "That didn't work.");
  }
  return (
    <div>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <button type="button" onClick={go} disabled={!csrf}>Re-run failed actions</button>
      <p className="hint">Failed records are re-executed as a new round with new idempotency keys.</p>
    </div>
  );
}
