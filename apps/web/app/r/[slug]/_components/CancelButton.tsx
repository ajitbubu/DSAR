"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { postJson, useCsrfToken } from "@/lib/client";

export function CancelButton() {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function cancel() {
    if (!csrf) return;
    const res = await postJson("/api/public/case/cancel", csrf);
    if (res.ok) router.refresh();
    else if (res.status === 409) setError("This request is already being processed and can't be withdrawn.");
    else setError("We couldn't withdraw your request. Please try again.");
  }

  if (!confirming) {
    return <button type="button" className="danger" onClick={() => setConfirming(true)}>Withdraw request</button>;
  }
  return (
    <div>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <p>Withdraw this request? We&apos;ll stop processing it. You can submit a new one later.</p>
      <div className="actions">
        <button type="button" className="danger" onClick={cancel}>Yes, withdraw</button>
        <button type="button" className="secondary" onClick={() => setConfirming(false)}>Keep my request</button>
      </div>
    </div>
  );
}
