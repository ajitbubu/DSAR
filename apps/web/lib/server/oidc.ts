import "server-only";
import * as client from "openid-client";

/**
 * Staff OIDC client (ADR-0003). The web server is a confidential client using the
 * authorization code flow with PKCE (S256), state and nonce. The IdP is Keycloak in dev
 * (production IdP is decision D-1).
 *
 * Discovery is fetched from the IdP's internal URL. With KC_HOSTNAME set, Keycloak
 * reports the public issuer and browser-facing authorize URL, and internal token URLs.
 */
let cached: Promise<client.Configuration> | null = null;

function env(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

export const oidcSettings = {
  get discoveryUrl() {
    return env("OIDC_DISCOVERY_URL", "http://localhost:8080/realms/idprivacy");
  },
  get clientId() {
    return env("OIDC_CLIENT_ID", "idprivacy-web");
  },
  get clientSecret() {
    return env("OIDC_CLIENT_SECRET");
  },
  get redirectUri() {
    return `${env("APP_ORIGIN", "http://localhost:3000")}/api/auth/callback`;
  },
};

async function load(): Promise<client.Configuration> {
  const base = oidcSettings.discoveryUrl.replace(/\/$/, "");
  const res = await fetch(`${base}/.well-known/openid-configuration`, { cache: "no-store" });
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  const metadata = (await res.json()) as client.ServerMetadata;
  const config = new client.Configuration(metadata, oidcSettings.clientId,
                                          oidcSettings.clientSecret);
  if (metadata.issuer.startsWith("http://")) client.allowInsecureRequests(config); // dev only
  return config;
}

export function oidcConfig(): Promise<client.Configuration> {
  cached ??= load().catch((err) => {
    cached = null;
    throw err;
  });
  return cached;
}

export { client };
