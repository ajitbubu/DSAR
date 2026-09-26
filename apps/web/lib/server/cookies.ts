import "server-only";

/**
 * All BFF cookies are httpOnly + Secure + SameSite=Strict with the __Host- prefix
 * (no Domain, Path=/), so script can't read them and subdomains can't overwrite them.
 * Browsers treat http://localhost as a secure context, so this also works locally.
 */
export const COOKIE = {
  csrf: "__Host-idp_csrf",
  challenge: "__Host-idp_challenge",
  dpSession: "__Host-idp_dp",
} as const;

export const baseCookie = {
  httpOnly: true,
  secure: true,
  sameSite: "strict" as const,
  path: "/",
};

export type PendingChallenge = {
  challengeId: string;
  displayId: string;
  destinationHint: string;
  slug: string;
};

export function encodeChallenge(value: PendingChallenge): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function decodeChallenge(raw: string | undefined): PendingChallenge | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    const uuid = /^[0-9a-f-]{36}$/;
    if (
      typeof parsed?.challengeId === "string" && uuid.test(parsed.challengeId) &&
      typeof parsed.displayId === "string" && typeof parsed.slug === "string" &&
      typeof parsed.destinationHint === "string"
    ) {
      return parsed as PendingChallenge;
    }
  } catch {
    // fall through
  }
  return null;
}
