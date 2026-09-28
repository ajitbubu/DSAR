import "server-only";
import { redirect } from "next/navigation";
import { isDroppedSocket } from "./api";
import { serverConfig } from "./config";
import { getStaffSession } from "./staff-session";

/** Calls a staff API as the signed-in user; sends them to login if the session is gone. */
export async function staffApi<T>(path: string, returnTo: string): Promise<
  { ok: true; data: T } | { ok: false; status: number }> {
  const session = await getStaffSession();
  if (!session) redirect(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  const get = () => fetch(`${serverConfig.apiBaseUrl}${path}`, {
    headers: { Authorization: `Bearer ${session.accessToken}`, Accept: "application/json" },
    cache: "no-store",
  });
  const res = await get().catch((err: unknown) => {
    if (isDroppedSocket(err)) return get();  // reads only; see callApi
    throw err;
  });
  if (res.status === 401) redirect(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  if (!res.ok) return { ok: false, status: res.status };
  return { ok: true, data: (await res.json()) as T };
}
