import "server-only";
import { randomBytes, timingSafeEqual } from "node:crypto";

export const CSRF_HEADER = "x-csrf-token";

export function newCsrfToken(): string {
  return randomBytes(32).toString("base64url");
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

export type CsrfInput = {
  method: string;
  origin: string | null;
  secFetchSite: string | null;
  contentType: string | null;
  headerToken: string | null;
  cookieToken: string | undefined;
  expectedOrigin: string;
};

/**
 * Returns null when the request may proceed, otherwise the reason it was rejected.
 * Layers (threat model T-06): exact Origin match, Sec-Fetch-Site same-origin, JSON-only
 * content type (no simple cross-site form posts), and a double-submit token matched in
 * constant time against the httpOnly cookie.
 */
export function checkCsrf(input: CsrfInput): string | null {
  if (["GET", "HEAD", "OPTIONS"].includes(input.method.toUpperCase())) return null;
  if (input.origin !== input.expectedOrigin) return "origin";
  if (input.secFetchSite && input.secFetchSite !== "same-origin") return "fetch-site";
  if (!input.contentType?.toLowerCase().startsWith("application/json")) return "content-type";
  if (!input.headerToken || !input.cookieToken) return "token-missing";
  if (!safeEqual(input.headerToken, input.cookieToken)) return "token-mismatch";
  return null;
}
