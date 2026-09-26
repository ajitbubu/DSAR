import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE, decodeChallenge } from "@/lib/server/cookies";
import { clientIp, guardedJson, problem, relay } from "@/lib/server/handler";

export async function POST(req: Request) {
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;
  const pending = decodeChallenge((await cookies()).get(COOKIE.challenge)?.value);
  if (!pending) return problem(410, "Verification session expired");
  const res = await callApi(`/v1/public/verifications/${pending.challengeId}/resend`, {
    method: "POST",
    clientIp: clientIp(req),
  });
  return relay(res);
}
