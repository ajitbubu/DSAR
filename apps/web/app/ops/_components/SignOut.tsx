"use client";

import { postJson, useCsrfToken } from "@/lib/client";

export function SignOut() {
  const csrf = useCsrfToken();
  async function signOut() {
    if (!csrf) return;
    const res = await postJson("/api/auth/logout", csrf);
    const body = (await res.json().catch(() => ({}))) as { redirect?: string };
    window.location.assign(body.redirect ?? "/");
  }
  return <button type="button" className="secondary" onClick={signOut} disabled={!csrf}>Sign out</button>;
}
