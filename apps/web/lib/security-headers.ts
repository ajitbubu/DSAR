/**
 * Baseline security headers applied to every response (threat model T-05, T-07).
 * A nonce-based Content-Security-Policy arrives with the first real pages in M1.
 */
export const securityHeaders: ReadonlyArray<{ key: string; value: string }> = [
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=()" },
];
