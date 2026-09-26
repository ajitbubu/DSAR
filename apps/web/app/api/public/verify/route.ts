import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE, baseCookie, decodeChallenge } from "@/lib/server/cookies";
import { clientIp, guardedJson, problem, relay } from "@/lib/server/handler";

export async function POST(req: Request) {
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;
  const jar = await cookies();
  const pending = decodeChallenge(jar.get(COOKIE.challenge)?.value);
  if (!pending) return problem(410, "Verification session expired");

  const res = await callApi(`/v1/public/verifications/${pending.challengeId}/confirm`, {
    method: "POST",
    body: guarded.body,
    clientIp: clientIp(req),
  });
  if (res.status !== 200) return relay(res);

  const data = (await res.json()) as { sessionToken: string };
  // The API enforces idle and absolute expiry; the cookie only needs to outlive them.
  jar.set(COOKIE.dpSession, data.sessionToken, { ...baseCookie, maxAge: 60 * 60 * 24 });
  jar.delete(COOKIE.challenge);
  return Response.json({ ok: true, slug: pending.slug }, { headers: { "Cache-Control": "no-store" } });
}
