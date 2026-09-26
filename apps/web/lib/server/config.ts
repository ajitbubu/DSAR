import "server-only";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

/** Server-side configuration. Nothing here is ever exposed to the browser. */
export const serverConfig = {
  get apiBaseUrl() {
    return process.env.API_BASE_URL ?? "http://localhost:8000";
  },
  get bffSharedSecret() {
    return required("BFF_SHARED_SECRET");
  },
  /** Exact origin the browser must present on state-changing requests (CSRF). */
  get appOrigin() {
    return process.env.APP_ORIGIN ?? "http://localhost:3000";
  },
  /** Dev convenience: show the mock OTP on the verify screen (API must run with ENV=test). */
  get devShowMockOtp() {
    return process.env.DEV_SHOW_MOCK_OTP === "true";
  },
};
