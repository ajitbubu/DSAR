import { cookies } from "next/headers";
import { safeReturnTo } from "@/lib/safe-redirect";
import { client, oidcConfig, oidcSettings } from "@/lib/server/oidc";
import { STAFF_COOKIE, createStaffSession, staffCookie } from "@/lib/server/staff-session";
import { problem } from "@/lib/server/handler";

export const dynamic = "force-dynamic";
const TXN = "__Host-idp_oidc";

export async function GET(req: Request) {
  const jar = await cookies();
  const raw = jar.get(TXN)?.value;
  jar.delete(TXN);
  if (!raw) return problem(400, "Login session expired");
  let txn: { verifier: string; state: string; nonce: string; returnTo: string };
  try {
    txn = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    return problem(400, "Bad Request");
  }
  // Rebuild the callback URL from the configured origin; the container sees an internal host.
  const incoming = new URL(req.url);
  const current = new URL(oidcSettings.redirectUri);
  current.search = incoming.search;
  try {
    const tokens = await client.authorizationCodeGrant(await oidcConfig(), current, {
      pkceCodeVerifier: txn.verifier,
      expectedState: txn.state,
      expectedNonce: txn.nonce,
      idTokenExpected: true,
    });
    const sid = await createStaffSession(tokens);
    jar.set(STAFF_COOKIE, sid, staffCookie);
  } catch {
    return problem(401, "Login failed");
  }
  const origin = new URL(oidcSettings.redirectUri).origin;
  return Response.redirect(`${origin}${safeReturnTo(txn.returnTo)}`, 302);
}
