"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";
import { useCsrfToken } from "@/lib/client";

const MAX = 10 * 1024 * 1024;

export function UploadForm({ caseId }: { caseId: string }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const input = useRef<HTMLInputElement>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const file = input.current?.files?.[0];
    if (!file || !csrf) return;
    if (file.size > MAX) {
      setMessage({ ok: false, text: "Files must be 10 MB or smaller." });
      return;
    }
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`/api/staff-upload/v1/cases/${caseId}/evidence`, {
      method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": csrf }, body: form,
    });
    if (res.ok) {
      setMessage({ ok: true, text: "Uploaded." });
      if (input.current) input.current.value = "";
      router.refresh();
    } else if (res.status === 415) {
      setMessage({ ok: false, text: "Only PDF, PNG and JPEG files are accepted, and the contents must match the type." });
    } else if (res.status === 413) {
      setMessage({ ok: false, text: "Files must be 10 MB or smaller." });
    } else if (res.status === 403) {
      setMessage({ ok: false, text: "Your role can't upload evidence." });
    } else {
      setMessage({ ok: false, text: "Upload failed." });
    }
  }

  return (
    <form className="decision-form" onSubmit={submit}>
      {message && <div className={message.ok ? "alert success" : "alert error-box"} role="status">{message.text}</div>}
      <label htmlFor="evidence-file" className="legend">Supporting document (PDF, PNG or JPEG, up to 10 MB)</label>
      <input id="evidence-file" ref={input} type="file" accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg" />
      <div className="actions"><button type="submit" disabled={!csrf}>Upload</button></div>
    </form>
  );
}
