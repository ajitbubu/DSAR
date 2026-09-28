"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

export function RetryButton({ caseId, taskId }: { caseId: string; taskId: string }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [error, setError] = useState<string | null>(null);
  async function retry() {
    if (!csrf) return;
    const r = await staffPost(`/v1/cases/${caseId}/fulfilment-tasks/${taskId}/retry`, csrf, {});
    if (r.ok) router.refresh();
    else setError(r.status === 403 ? "Your role can't retry tasks." : r.title ?? "Retry failed.");
  }
  return (
    <>
      <button type="button" className="secondary decision-toggle" onClick={retry} disabled={!csrf}>
        Retry with the same key
      </button>
      {error && <p className="error">{error}</p>}
    </>
  );
}
