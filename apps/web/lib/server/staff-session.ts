import "server-only";
import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { createClient } from "redis";
import { client, oidcConfig } from "./oidc";

/**
 * Server-side staff sessions (ADR-0003). The browser holds only an opaque 256-bit id in
 * an httpOnly cookie. Tokens live in Redis under the SHA-256 of that id, so a Redis dump
 * doesn't yield usable cookies. Absolute lifetime is 8 hours (decision D-13).
 */
export const STAFF_COOKIE = "__Host-idp_staff";
const ABSOLUTE_SECONDS = 8 * 60 * 60;

type StoredSession = {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  accessExpiresAt: number;
  createdAt: number;
  subject: string;
};

/** The three Redis operations sessions need (keeps us clear of the client's generics). */
type Store = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options: { EX: number }): Promise<unknown>;
  del(key: string): Promise<unknown>;
};
let redis: Promise<Store> | null = null;

function store(): Promise<Store> {
  if (!redis) {
    const pending = createClient({ url: process.env.REDIS_URL ?? "redis://localhost:16379/1" })
      .on("error", () => undefined)
      .connect() as unknown as Promise<Store>;
    redis = pending.catch((err: unknown) => {
      redis = null;
      throw err;
    });
  }
  return redis;
}

const key = (sid: string) => `staff-session:${createHash("sha256").update(sid).digest("hex")}`;

export const staffCookie = {
  httpOnly: true,
  secure: true,
  // Lax, not Strict: the login redirect chain starts at the IdP (cross-site). State
  // changes are still protected by the CSRF token and the Origin check.
  sameSite: "lax" as const,
  path: "/",
  maxAge: ABSOLUTE_SECONDS,
};

export async function createStaffSession(tokens: client.TokenEndpointResponse &
  client.TokenEndpointResponseHelpers): Promise<string> {
  const sid = randomBytes(32).toString("base64url");
  const claims = tokens.claims();
  const now = Math.floor(Date.now() / 1000);
  const session: StoredSession = {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    idToken: tokens.id_token,
    accessExpiresAt: now + (tokens.expiresIn() ?? 60),
    createdAt: now,
    subject: String(claims?.sub ?? ""),
  };
  await (await store()).set(key(sid), JSON.stringify(session), { EX: ABSOLUTE_SECONDS });
  return sid;
}

export type StaffSession = { accessToken: string; idToken?: string; sid: string };

/** Returns the current session, refreshing the access token when it's about to expire. */
export async function getStaffSession(): Promise<StaffSession | null> {
  const sid = (await cookies()).get(STAFF_COOKIE)?.value;
  if (!sid || sid.length > 100) return null;
  const db = await store();
  const raw = await db.get(key(sid));
  if (!raw) return null;
  const session = JSON.parse(raw) as StoredSession;
  const now = Math.floor(Date.now() / 1000);
  if (session.accessExpiresAt - 30 > now) {
    return { accessToken: session.accessToken, idToken: session.idToken, sid };
  }
  if (!session.refreshToken) return null;
  try {
    const refreshed = await client.refreshTokenGrant(await oidcConfig(), session.refreshToken);
    const updated: StoredSession = {
      ...session,
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token ?? session.refreshToken,
      idToken: refreshed.id_token ?? session.idToken,
      accessExpiresAt: now + (refreshed.expiresIn() ?? 60),
    };
    const ttl = Math.max(1, session.createdAt + ABSOLUTE_SECONDS - now);
    await db.set(key(sid), JSON.stringify(updated), { EX: ttl });
    return { accessToken: updated.accessToken, idToken: updated.idToken, sid };
  } catch {
    await db.del(key(sid));
    return null;
  }
}

export async function destroyStaffSession(sid: string): Promise<void> {
  await (await store()).del(key(sid));
}
