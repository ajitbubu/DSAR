import { STAFF_DOWNLOAD } from "@/lib/staff-actions";
import { serverConfig } from "@/lib/server/config";
import { problem } from "@/lib/server/handler";
import { getStaffSession } from "@/lib/server/staff-session";

export const dynamic = "force-dynamic";

/** Streams an evidence file from the API as the signed-in user (audited by the API). */
export async function GET(_req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const target = `/${(await ctx.params).path.join("/")}`;
  if (!STAFF_DOWNLOAD.test(target)) return problem(404, "Not Found");
  const session = await getStaffSession();
  if (!session) return problem(401, "Not authenticated");
  const res = await fetch(`${serverConfig.apiBaseUrl}${target}`, {
    headers: { Authorization: `Bearer ${session.accessToken}` }, cache: "no-store",
  });
  if (!res.ok || !res.body) return problem(res.status === 403 ? 403 : 404, "Not Found");
  const headers = new Headers({ "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  for (const h of ["content-type", "content-disposition", "content-length", "x-content-sha256"]) {
    const v = res.headers.get(h);
    if (v) headers.set(h, v);
  }
  return new Response(res.body, { status: 200, headers });
}
