"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { postJson, useCsrfToken } from "@/lib/client";
import { type ContactChannel, LIMITS, validateSignIn } from "@/lib/validation";

export function SignInForm({ slug }: { slug: string }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [reference, setReference] = useState("");
  const [channel, setChannel] = useState<ContactChannel>("EMAIL");
  const [contact, setContact] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const problem = validateSignIn(reference, channel, contact);
    setError(problem);
    if (problem || !csrf) return;
    setBusy(true);
    try {
      const res = await postJson("/api/public/sessions", csrf, {
        intakeSlug: slug,
        reference: reference.trim().toUpperCase(),
        contact: { channel, value: contact.trim() },
      });
      if (res.status === 202) {
        router.push(`/r/${slug}/verify`);
        return;
      }
      setError(res.status === 429
        ? "Too many attempts. Try again in a few minutes."
        : "We couldn't send a code. Check your details and try again.");
    } catch {
      setError("We couldn't reach the server. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} noValidate>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <div className="field">
        <label htmlFor="reference">Request reference</label>
        <input id="reference" type="text" autoComplete="off" maxLength={20} value={reference}
               placeholder="DPR-2026-AB12CD" onChange={(e) => setReference(e.target.value)} />
      </div>
      <fieldset className="field plain">
        <legend className="legend">Contact you used</legend>
        <div className="segmented">
          {(["EMAIL", "SMS"] as const).map((ch) => (
            <label key={ch}>
              <input type="radio" name="channel" value={ch} checked={channel === ch}
                     onChange={() => setChannel(ch)} />
              <span>{ch === "EMAIL" ? "Email" : "Mobile (SMS)"}</span>
            </label>
          ))}
        </div>
        <label htmlFor="signin-contact" className="legend">
          {channel === "EMAIL" ? "Email address" : "Mobile number"}
        </label>
        <input id="signin-contact" type={channel === "EMAIL" ? "email" : "tel"}
               autoComplete={channel === "EMAIL" ? "email" : "tel"} maxLength={LIMITS.contact}
               value={contact} onChange={(e) => setContact(e.target.value)} />
      </fieldset>
      <div className="actions">
        <button type="submit" disabled={busy || !csrf}>{busy ? "Sending…" : "Send code"}</button>
      </div>
    </form>
  );
}
