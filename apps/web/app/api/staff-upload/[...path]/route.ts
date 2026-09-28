import { cookies } from "next/headers";
import { STAFF_UPLOAD } from "@/lib/staff-actions";
import { serverConfig } from "@/lib/server/config";
import { COOKIE } from "@/lib/server/cookies";
import { CSRF_HEADER, checkCsrf } from "@/lib/server/csrf";
import { problem, relay } from "@/lib/server/handler";
import { getStaffSession } from "@/lib/server/staff-session";

const MAX_UPLOAD = 10 * 1024 * 1024 + 64 * 1024;

/** CSRF-guarded multipart upload proxy. The API validates the file itself. */
export async function POST(req: Request, ctx: { params: Promise<{ path: string[] }> }) {
  const target = `/${(await ctx.params).path.join("/")}`;
  if (!STAFF_UPLOAD.test(target)) return problem(404, "Not Found");
  const contentType = req.headers.get("content-type");
  const reason = checkCsrf({
    method: req.method, origin: req.headers.get("origin"),
    secFetchSite: req.headers.get("sec-fetch-site"), contentType,
    headerToken: req.headers.get(CSRF_HEADER), cookieToken: (await cookies()).get(COOKIE.csrf)?.value,
    expectedOrigin: serverConfig.appOrigin, allowedContentType: "multipart/form-data",
  });
  if (reason) return problem(403, "Forbidden");
  if (Number(req.headers.get("content-length") ?? "0") > MAX_UPLOAD) {
    return problem(413, "Payload Too Large");
  }
  const session = await getStaffSession();
  if (!session) return problem(401, "Not authenticated");
  const body = await req.arrayBuffer();
  if (body.byteLength > MAX_UPLOAD) return problem(413, "Payload Too Large");
  return relay(await fetch(`${serverConfig.apiBaseUrl}${target}`, {
    method: "POST", body,
    headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": contentType! },
  }));
}
