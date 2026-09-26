import { cookies } from "next/headers";
import { callApi } from "@/lib/server/api";
import { COOKIE, baseCookie, encodeChallenge } from "@/lib/server/cookies";
import { clientIp, guardedJson, relay } from "@/lib/server/handler";

export async function POST(req: Request) {
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;

  const res = await callApi("/v1/public/requests", {
    method: "POST",
    body: guarded.body,
    clientIp: clientIp(req),
  });
  if (res.status !== 202) return relay(res);

  const data = (await res.json()) as {
    displayId: string;
    challengeId: string;
    destinationHint: string;
  };
  const slug = String((guarded.body as { intakeSlug?: unknown }).intakeSlug ?? "");
  const jar = await cookies();
  // The challenge id stays in an httpOnly cookie, never in a browser-visible URL.
  jar.set(
    COOKIE.challenge,
    encodeChallenge({ challengeId: data.challengeId, displayId: data.displayId,
                      destinationHint: data.destinationHint, slug }),
    { ...baseCookie, maxAge: 60 * 30 },
  );
  return Response.json(
    { displayId: data.displayId, destinationHint: data.destinationHint },
    { status: 202, headers: { "Cache-Control": "no-store" } },
  );
}
