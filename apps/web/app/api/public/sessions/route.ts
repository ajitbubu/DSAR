import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE, baseCookie, encodeChallenge } from "@/lib/server/cookies";
import { clientIp, guardedJson, relay } from "@/lib/server/handler";

/** Returning sign-in: relays to the API and keeps the challenge id in an httpOnly cookie. */
export async function POST(req: Request) {
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;
  const res = await callApi("/v1/public/sessions", {
    method: "POST",
    body: guarded.body,
    clientIp: clientIp(req),
  });
  if (res.status !== 202) return relay(res);
  const data = (await res.json()) as { challengeId: string; destinationHint: string };
  const body = guarded.body as { intakeSlug?: unknown; reference?: unknown };
  (await cookies()).set(
    COOKIE.challenge,
    encodeChallenge({
      challengeId: data.challengeId,
      displayId: String(body.reference ?? ""),
      destinationHint: data.destinationHint,
      slug: String(body.intakeSlug ?? ""),
    }),
    { ...baseCookie, maxAge: 60 * 30 },
  );
  return Response.json(
    { destinationHint: data.destinationHint },
    { status: 202, headers: { "Cache-Control": "no-store" } },
  );
}
