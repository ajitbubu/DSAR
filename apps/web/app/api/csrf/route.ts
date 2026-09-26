import { cookies } from "next/headers";
import { COOKIE, baseCookie } from "@/lib/server/cookies";
import { newCsrfToken } from "@/lib/server/csrf";

export const dynamic = "force-dynamic";

/** Issues (or re-issues) the double-submit CSRF token. Readable only by same-origin JS. */
export async function GET() {
  const jar = await cookies();
  const token = jar.get(COOKIE.csrf)?.value ?? newCsrfToken();
  jar.set(COOKIE.csrf, token, { ...baseCookie, maxAge: 60 * 60 * 8 });
  return Response.json({ token }, { headers: { "Cache-Control": "no-store" } });
}
