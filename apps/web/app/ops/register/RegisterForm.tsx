"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../_components/staffPost";

type Recipient = { name: string; kind: string };
type Props = { connectorId: string; purposes: string[]; recipients: Recipient[] };
const KINDS = ["PROCESSOR", "FIDUCIARY", "OTHER"];

/** One line per purpose; recipients as "Name | KIND" lines. */
export function parseRecipients(text: string): Recipient[] | null {
  const out: Recipient[] = [];
  for (const line of text.split("\n").map((l) => l.trim()).filter(Boolean)) {
    const [name, kind = "PROCESSOR"] = line.split("|").map((p) => p.trim());
    if (!name || !KINDS.includes(kind.toUpperCase())) return null;
    out.push({ name, kind: kind.toUpperCase() });
  }
  return out;
}

export function RegisterForm({ connectorId, purposes, recipients }: Props) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [open, setOpen] = useState(false);
  const [purposeText, setPurposeText] = useState(purposes.join("\n"));
  const [recipientText, setRecipientText] = useState(
    recipients.map((r) => `${r.name} | ${r.kind}`).join("\n"),
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const ps = purposeText.split("\n").map((l) => l.trim()).filter(Boolean);
    const rs = parseRecipients(recipientText);
    if (ps.length === 0) return setError("Add at least one purpose.");
    if (rs === null) return setError(`Write recipients as "Name | ${KINDS.join(" or ")}".`);
    if (!csrf) return;
    setBusy(true);
    setError(null);
    const r = await staffPost(`/v1/processing-register/${connectorId}`, csrf, { purposes: ps, recipients: rs });
    setBusy(false);
    if (r.ok) {
      setOpen(false);
      router.refresh();
    } else {
      setError(r.status === 403 ? "Only a tenant admin can change the register." : r.title ?? "That didn't work.");
    }
  }

  if (!open) {
    return <button type="button" className="secondary" onClick={() => setOpen(true)}>Edit</button>;
  }
  return (
    <form className="register-form" onSubmit={submit} noValidate>
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <label className="legend" htmlFor={`p-${connectorId}`}>Purposes (one per line)</label>
      <textarea id={`p-${connectorId}`} value={purposeText} maxLength={2000}
                onChange={(e) => setPurposeText(e.target.value)} />
      <label className="legend" htmlFor={`r-${connectorId}`}>Recipients (one per line: Name | PROCESSOR, FIDUCIARY or OTHER)</label>
      <textarea id={`r-${connectorId}`} value={recipientText} maxLength={4000}
                onChange={(e) => setRecipientText(e.target.value)} />
      <div className="actions">
        <button type="submit" disabled={busy || !csrf}>Save new version</button>
        <button type="button" className="secondary" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </form>
  );
}
