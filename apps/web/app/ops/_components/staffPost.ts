"use client";

import { postJson } from "@/lib/client";

export type ApiResult = { ok: boolean; status: number; title?: string };

/** POST through the BFF's allowlisted staff proxy. */
export async function staffPost(apiPath: string, csrf: string, body: unknown,
                                headers: Record<string, string> = {}): Promise<ApiResult> {
  const res = await postJson(`/api/staff${apiPath}`, csrf, body, headers);
  const data = (await res.json().catch(() => ({}))) as { title?: string };
  return { ok: res.ok, status: res.status, title: data.title };
}
