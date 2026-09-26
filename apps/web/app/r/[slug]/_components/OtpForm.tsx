"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { postJson, useCsrfToken } from "@/lib/client";
import { OTP_PATTERN } from "@/lib/validation";

type Props = { slug: string; destinationHint: string };

export function OtpForm({ slug, destinationHint }: Props) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [locked, setLocked] = useState(false);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    if (!OTP_PATTERN.test(code)) {
      setError("Enter the 6-digit code.");
      return;
    }
    if (!csrf) return;
    setBusy(true);
    setError(null);
    try {
      const res = await postJson("/api/public/verify", csrf, { code });
      if (res.ok) {
        router.push(`/r/${slug}/status`);
        return;
      }
      if (res.status === 422) setError("That code isn't right. Check it and try again.");
      else if (res.status === 410) setError("This code has expired. Send a new one below.");
      else if (res.status === 409) setError("This code was already used.");
      else if (res.status === 429) {
        setLocked(true);
        setError("Too many attempts. For your security this request can't be verified. Please submit a new request.");
      } else setError("Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    if (!csrf) return;
    setError(null);
    setNotice(null);
    const res = await postJson("/api/public/resend", csrf);
    if (res.status === 202) setNotice("We've sent a new code.");
    else if (res.status === 429) setError("Please wait a little before asking for another code.");
    else setError("We couldn't send a new code. Please try again.");
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      <p className="lede">We sent a 6-digit code to <strong>{destinationHint}</strong>. It expires in 10 minutes.</p>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      {notice && <div className="alert success" role="status">{notice}</div>}
      <div className="field">
        <label htmlFor="code">Verification code</label>
        <input id="code" className="otp" type="text" inputMode="numeric" autoComplete="one-time-code"
               pattern="\d{6}" maxLength={6} value={code} disabled={locked}
               onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
               aria-invalid={error ? true : undefined} />
      </div>
      <div className="actions">
        <button type="submit" disabled={busy || locked}>{busy ? "Checking…" : "Verify"}</button>
        <button type="button" className="secondary" onClick={resend} disabled={locked}>
          Send a new code
        </button>
      </div>
    </form>
  );
}
