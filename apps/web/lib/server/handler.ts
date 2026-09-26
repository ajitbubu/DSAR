import "server-only";
import { cookies } from "next/headers";
import { COOKIE } from "./cookies";
import { CSRF_HEADER, checkCsrf } from "./csrf";
import { serverConfig } from "./config";

const MAX_BODY_BYTES = 64 * 1024;

export function problem(status: number, title: string): Response {
  return Response.json(
    { type: "about:blank", title, status },
    { status, headers: { "Content-Type": "application/problem+json", "Cache-Control": "no-store" } },
  );
}

export function clientIp(req: Request): string {
  // First hop only; the Next server sets x-forwarded-for from the socket address.
  return (req.headers.get("x-forwarded-for") ?? "").split(",")[0]?.trim().slice(0, 64) ?? "";
}

/** CSRF-checks a state-changing BFF request and parses its bounded JSON body. */
export async function guardedJson(req: Request): Promise<{ body: unknown } | Response> {
  const jar = await cookies();
  const reason = checkCsrf({
    method: req.method,
    origin: req.headers.get("origin"),
    secFetchSite: req.headers.get("sec-fetch-site"),
    contentType: req.headers.get("content-type"),
    headerToken: req.headers.get(CSRF_HEADER),
    cookieToken: jar.get(COOKIE.csrf)?.value,
    expectedOrigin: serverConfig.appOrigin,
  });
  if (reason) return problem(403, "Forbidden");
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) return problem(413, "Payload Too Large");
  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) return problem(413, "Payload Too Large");
  if (!text) return { body: undefined };
  try {
    return { body: JSON.parse(text) };
  } catch {
    return problem(400, "Bad Request");
  }
}

/** Relays an API response to the browser without leaking internal headers. */
export async function relay(res: Response): Promise<Response> {
  const text = await res.text();
  return new Response(text, {
    status: res.status,
    headers: {
      "Content-Type": res.headers.get("content-type") ?? "application/json",
      "Cache-Control": "no-store",
      ...(res.headers.get("retry-after") ? { "Retry-After": res.headers.get("retry-after")! } : {}),
    },
  });
}
