/**
 * Only same-site relative paths under the operations console are allowed as post-login
 * targets. This blocks open redirects like "//evil.example" or "https://evil.example".
 */
export function safeReturnTo(raw: string | null | undefined, fallback = "/ops"): string {
  if (!raw || raw.length > 512) return fallback;
  if (!raw.startsWith("/ops") || raw.startsWith("//") || raw.includes("\\")) return fallback;
  try {
    const url = new URL(raw, "http://placeholder.invalid");
    if (url.origin !== "http://placeholder.invalid") return fallback;
    // Check again after normalisation: "/ops/../api/x" resolves to "/api/x".
    if (url.pathname !== "/ops" && !url.pathname.startsWith("/ops/")) return fallback;
    return `${url.pathname}${url.search}`;
  } catch {
    return fallback;
  }
}
