import { cookies } from "next/headers";
import { guardedJson } from "@/lib/server/handler";
import { client, oidcConfig } from "@/lib/server/oidc";
import { STAFF_COOKIE, destroyStaffSession, getStaffSession } from "@/lib/server/staff-session";

/** CSRF-protected logout: drops the server-side session, then ends the IdP session. */
export async function POST(req: Request) {
  const guarded = await guardedJson(req);
  if (guarded instanceof Response) return guarded;
  const session = await getStaffSession();
  const jar = await cookies();
  jar.delete(STAFF_COOKIE);
  if (session) await destroyStaffSession(session.sid);
  const origin = process.env.APP_ORIGIN ?? "http://localhost:3000";
  const endSession = client.buildEndSessionUrl(await oidcConfig(), {
    post_logout_redirect_uri: `${origin}/`,
    ...(session?.idToken ? { id_token_hint: session.idToken } : {}),
  });
  return Response.json({ redirect: endSession.href }, { headers: { "Cache-Control": "no-store" } });
}
