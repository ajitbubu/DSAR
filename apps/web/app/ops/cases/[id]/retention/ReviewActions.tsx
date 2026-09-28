"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

type Props = { caseId: string; status: string; version: number; unresolved: number };

export function ReviewActions({ caseId, status, version, unresolved }: Props) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function fire(event: string) {
    if (!csrf) return;
    setBusy(true);
    setError(null);
    const r = await staffPost(`/v1/cases/${caseId}/transitions`, csrf,
                              { event, expected_version: version });
    setBusy(false);
    if (r.ok) router.refresh();
    else setError(r.status === 403 ? "Your role can't do this." : r.title ?? "That didn't work.");
  }

  return (
    <div>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      {status === "RETENTION_EVALUATED" && (
        <button type="button" onClick={() => fire("BEGIN_REVIEW")} disabled={busy || !csrf}>
          Start review
        </button>
      )}
      {status === "REJECTED" && (
        <button type="button" onClick={() => fire("REWORK")} disabled={busy || !csrf}>
          Resume review
        </button>
      )}
      {status === "UNDER_REVIEW" && (
        <div className="actions">
          <button type="button" onClick={() => fire("SUBMIT_FOR_APPROVAL")}
                  disabled={busy || !csrf || unresolved > 0}>
            Submit for approval
          </button>
          {unresolved > 0 && (
            <span className="hint">
              Resolve {unresolved} record{unresolved === 1 ? "" : "s"} marked “Needs review” first.
            </span>
          )}
        </div>
      )}
    </div>
  );
}
