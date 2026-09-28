"use client";

import { useEffect, useState } from "react";

/** Fetches the double-submit CSRF token once per page. */
export function useCsrfToken(): string | null {
  const [token, setToken] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    fetch("/api/csrf", { credentials: "same-origin", cache: "no-store" })
      .then((r) => r.json())
      .then((d: { token: string }) => active && setToken(d.token))
      .catch(() => active && setToken(null));
    return () => {
      active = false;
    };
  }, []);
  return token;
}

export async function postJson(url: string, csrf: string, body?: unknown,
                               extraHeaders: Record<string, string> = {}): Promise<Response> {
  return fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf, ...extraHeaders },
    body: JSON.stringify(body ?? {}),
  });
}
