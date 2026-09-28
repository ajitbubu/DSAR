"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

export function ExportButton({ caseId, again }: { caseId: string; again: boolean }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function start() {
    if (!csrf) return;
    setBusy(true);
    setError(null);
    const r = await staffPost(`/v1/cases/${caseId}/disclosure/exports`, csrf, {});
    setBusy(false);
    if (r.ok) router.refresh();
    else setError(r.status === 403 ? "Your role can't do this." : r.title ?? "That didn't work.");
  }

  return (
    <div>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <button type="button" className={again ? "secondary" : undefined} onClick={start}
              disabled={busy || !csrf}>
        {again ? "Export again (clears exclusions)" : "Export records"}
      </button>
    </div>
  );
}

/** Re-renders the server page every two seconds while an export is running. */
export function RefreshWhilePending() {
  const router = useRouter();
  useEffect(() => {
    const t = setInterval(() => router.refresh(), 2000);
    return () => clearInterval(t);
  }, [router]);
  return <p className="hint" role="status">Exporting records from the source systems…</p>;
}
