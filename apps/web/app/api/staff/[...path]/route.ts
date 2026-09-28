import { isAllowedStaffMutation } from "@/lib/staff-actions";
import { serverConfig } from "@/lib/server/config";
import { guardedJson, problem, relay } from "@/lib/server/handler";
import { getStaffSession } from "@/lib/server/staff-session";

/** CSRF-guarded proxy for allowlisted staff mutations, sent as the signed-in user. */
export async function POST(req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const target = `/${path.join("/")}`;
  if (!isAllowedStaffMutation(target)) return problem(404, "Not Found");
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;
  const session = await getStaffSession();
  if (!session) return problem(401, "Not authenticated");
  const res = await fetch(`${serverConfig.apiBaseUrl}${target}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json",
               Accept: "application/json" },
    body: JSON.stringify(guarded.body ?? {}),
    cache: "no-store",
  });
  return relay(res);
}
