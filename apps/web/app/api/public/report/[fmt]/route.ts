import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE } from "@/lib/server/cookies";
import { clientIp, problem, relay } from "@/lib/server/handler";

export const dynamic = "force-dynamic";
const FORMATS = new Set(["json", "html"]);
const PASS = ["content-type", "content-disposition", "content-security-policy"];

/** Relays the requester's report download. The API checks the session, limits and audit. */
export async function GET(req: Request, ctx: { params: Promise<{ fmt: string }> }) {
  const { fmt } = await ctx.params;
  if (!FORMATS.has(fmt)) return problem(404, "Not Found");
  const token = (await cookies()).get(COOKIE.dpSession)?.value;
  if (!token) return problem(401, "Not authenticated");
  const res = await callApi(`/v1/public/case/report/${fmt}`, { dpSession: token, clientIp: clientIp(req) });
  if (!res.ok || !res.body) return relay(res);
  const headers = new Headers({ "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  for (const h of PASS) {
    const v = res.headers.get(h);
    if (v) headers.set(h, v);
  }
  return new Response(res.body, { status: 200, headers });
}
