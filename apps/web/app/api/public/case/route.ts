import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE } from "@/lib/server/cookies";
import { clientIp, problem, relay } from "@/lib/server/handler";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const token = (await cookies()).get(COOKIE.dpSession)?.value;
  if (!token) return problem(401, "Not authenticated");
  return relay(await callApi("/v1/public/case", { dpSession: token, clientIp: clientIp(req) }));
}
