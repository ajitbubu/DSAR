import { cookies } from "next/headers";
import { safeReturnTo } from "@/lib/safe-redirect";
import { client, oidcConfig, oidcSettings } from "@/lib/server/oidc";

export const dynamic = "force-dynamic";
const OIDC_TXN_COOKIE = "__Host-idp_oidc";

/** Starts staff login: PKCE + state + nonce, kept in a short-lived httpOnly cookie. */
export async function GET(req: Request) {
  const config = await oidcConfig();
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  (await cookies()).set(OIDC_TXN_COOKIE,
    Buffer.from(JSON.stringify({ verifier, state, nonce, returnTo })).toString("base64url"),
    // Lax so the cookie survives the cross-site redirect back from the IdP.
    { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 600 });
  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: oidcSettings.redirectUri,
    scope: "openid",
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });
  return Response.redirect(url.href, 302);
}
