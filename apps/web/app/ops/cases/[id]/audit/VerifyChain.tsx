"use client";

import { useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { postJson } from "@/lib/client";

export function VerifyChain() {
  const csrf = useCsrfToken();
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  async function verify() {
    if (!csrf) return;
    const res = await postJson("/api/staff/v1/audit/verify", csrf, {});
    if (res.status === 403) return setResult({ ok: false, text: "Only auditors can verify the chain." });
    const body = (await res.json()) as { ok: boolean; events_checked: number; first_broken_seq: number | null };
    setResult(body.ok
      ? { ok: true, text: `Chain intact: ${body.events_checked} events verified for your organisation.` }
      : { ok: false, text: `Chain broken at event ${body.first_broken_seq}.` });
  }
  return (
    <div>
      {result && <div className={result.ok ? "alert success" : "alert error-box"} role="status">{result.text}</div>}
      <button type="button" className="secondary" onClick={verify} disabled={!csrf}>Verify hash chain</button>
    </div>
  );
}
