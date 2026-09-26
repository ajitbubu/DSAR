import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE } from "@/lib/server/cookies";
import { clientIp, guardedJson, problem, relay } from "@/lib/server/handler";

export async function POST(req: Request) {
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;
  const token = (await cookies()).get(COOKIE.dpSession)?.value;
  if (!token) return problem(401, "Not authenticated");
  return relay(
    await callApi("/v1/public/case/cancel", {
      method: "POST",
      dpSession: token,
      clientIp: clientIp(req),
    }),
  );
}
